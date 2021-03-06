#include "DemoServer.h"

using namespace dsrv;

muduo::AsyncLogging* g_asyncLog = NULL;

string dsrv::utcToLocalTimeString(Timestamp utcTimestamp)
{
  return muduo::addTime(utcTimestamp,28800).toFormattedString(false);
}

string dsrv::getLocalTimeString()//thread safe
{
  char strTime[400];
  time_t rawTime;
  struct tm lcTime={0};
  time(&rawTime);
  localtime_r(&rawTime,&lcTime);//thread safe
  strftime(strTime,sizeof(strTime),"%Y-%m-%d %H:%M:%S",&lcTime);
  return string(strTime);
}

void dsrv::asyncOutput(const char* msg, int len)
{
  g_asyncLog->append(msg, len);
}

DemoServer::DemoServer(EventLoop* loop,InetAddress& listenAddr,
		       int numThreads,bool isAntiPiracy,
		       int idleSeconds,MysqlConnInfo mysqlConnInfo)
  :isAntiPiracy_(isAntiPiracy),idleSeconds_(idleSeconds),
   loop_(loop),server_(loop, listenAddr, "DemoServer"),
   mysqlConnInfo_(mysqlConnInfo)
{
  server_.setConnectionCallback(
				boost::bind(&DemoServer::onConnection, this, _1));
  server_.setMessageCallback(
			     boost::bind(&DemoServer::onMessage, this, _1, _2, _3));
  server_.setThreadNum(numThreads);

}

void DemoServer::start()
{
  server_.setThreadInitCallback(boost::bind(&DemoServer::threadInit, this, _1));
  server_.start();
}

void DemoServer::onConnection(const TcpConnectionPtr& conn)
{
  debugPrint("[%s,%s] DemoServer: - %s -> %s is %s\n",
	     getLocalTimeString().c_str(),
	     conn->peerAddress().toIpPort().c_str(),
	     conn->peerAddress().toIpPort().c_str(),
	     conn->localAddress().toIpPort().c_str(),
	     (conn->connected()?"UP":"DOWN"));

  if(conn->connected())
    {
      //time wheeling for kicking idle connection out
      EntryPtr entry(new Entry(conn));
      LocalWeakConnectionList::instance().back().insert(entry);
      WeakEntryPtr weakEntry(entry);
      conn->setContext(weakEntry);
      
      if(isAntiPiracy_)
	{
	  //first step to register a connection where the server is still blind to the clientID
	  addToUnauthorizedConns(WeakTcpConnectionPtr(conn));
	}
    }
  else
    {
      if(isAntiPiracy_)
	{
	  //unregister a connection
	  unAuthorize(WeakTcpConnectionPtr(conn));
	}
    }
}

void DemoServer::onTimer()
{
  LocalWeakConnectionList::instance().push_back(Bucket());
}

void DemoServer::threadInit(EventLoop* loop)
{
  LocalWeakConnectionList::instance().resize(idleSeconds_);
  loop->runEvery(1.0,boost::bind(&DemoServer::onTimer,this));
  {
    MutexLockGuard mtx(mysqlInitMutex_);
    mysql_init(&LocalMysqlConnection::instance());//mysql_init() is not thread safe when it is called by multiple threads at the same time
    
    char optVal=1;
    mysql_options(&LocalMysqlConnection::instance(),MYSQL_OPT_RECONNECT,(char*)&optVal);//deal with long lifetime mysql connection
    if(!(mysql_real_connect(&LocalMysqlConnection::instance(),
			    mysqlConnInfo_.host.c_str(),mysqlConnInfo_.user.c_str()
			    ,mysqlConnInfo_.passwd.c_str(),mysqlConnInfo_.db.c_str(),
			    0,NULL,0)))
      {
	debugPrint("[%s] FATAL: mysql connection error %d : %s",
		   getLocalTimeString().c_str(),
		   mysql_errno(&LocalMysqlConnection::instance()),
		   mysql_error(&LocalMysqlConnection::instance()));
	LOG_FATAL<<"["<<getLocalTimeString()<<"]"
		 <<" mysql connection error "
		 <<mysql_errno(&LocalMysqlConnection::instance())
		 <<":"<<mysql_error(&LocalMysqlConnection::instance());
      }
  }
}

void DemoServer::addToUnauthorizedConns(const WeakTcpConnectionPtr& weakConn)//thread safe
{
  MutexLockGuard mtx(mutex_);
  unauthorizedConns_.emplace(weakConn);
}

void DemoServer::unAuthorize(const WeakTcpConnectionPtr& weakConn)//thread safe
{
  MutexLockGuard mtx(mutex_);
  unauthorizedConns_.erase(weakConn);
  auto search=authorizedConnID_.find(weakConn);
  if(search!=authorizedConnID_.end())
    {
      int clientId=search->second;
      authorizedConnID_.erase(search);
      authorizedIDConn_.erase(clientId);
    }
}

bool DemoServer::authorize(const WeakTcpConnectionPtr& weakConn,int clientID)//thread safe
{
  //detect whether a clientID is legal.
  //basically one clientID ties with one connection ,and vice versa.
  //return false when a pirate has been detected,both connections with the same clientID would be removed immediatelly.
  MutexLockGuard mtx(mutex_);
  auto search=unauthorizedConns_.find(weakConn);
  if(search==unauthorizedConns_.end())
    {
      //quick check for authorization
      return true;//the client has been authorized already which is the most common case
    }
  else
    {
      auto search2=authorizedIDConn_.find(clientID);
      if(search2==authorizedIDConn_.end())//no collision has been detected 
	{
	  //authorizing the new client
	  unauthorizedConns_.erase(search);//erase from the unauthorized set which leads to a quick authorization check on its next arrival
	  authorizedConnID_.emplace(weakConn,clientID);//register
	  authorizedIDConn_.emplace(clientID,weakConn);//register
	  return true;
	}
      else
	{
	  //collision has been found(deal with the pirate situation)
	  
	  auto conn=weakConn.lock();
	  if(conn)
	    {
	      debugPrint("[%s,%s] ANTI-PIRACY: client ID collision occured with ID:%d\n",
			 getLocalTimeString().c_str(),
			 conn->peerAddress().toIpPort().c_str(),
			 clientID);
	      LOG_WARN<<"["<<getLocalTimeString()<<","
		      <<conn->peerAddress().toIpPort()
		      <<"] ANTI-PIRACY: client ID collison occured with ID:"
		      <<clientID;
	      conn->forceClose();//unauthorization for weakconn is operated in onConnection()
	    }
	  auto weakConnPrevious=search2->second;
	  auto connPrevious=weakConnPrevious.lock();
	  if(connPrevious)
	    {
	      connPrevious->forceClose();//unauthorization for weakconnprevious is operated in onConnection()
	    }
    
	  return false;
	}
    }
}
