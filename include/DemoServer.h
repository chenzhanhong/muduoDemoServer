#ifndef MUDUO_DEMOSERVER_H
#define MUDUO_DEMOSERVER_H

#include <muduo/base/Types.h>
#include <muduo/base/Timestamp.h>
#include <muduo/base/Logging.h>
#include <muduo/net/EventLoop.h>
#include <muduo/net/TcpServer.h>
#include <muduo/base/Mutex.h>
#include <muduo/base/ThreadLocalSingleton.h>
#include <muduo/base/AsyncLogging.h>

#include <boost/bind.hpp>
#include <boost/ref.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/unordered_set.hpp>
#include <boost/version.hpp>
#include <boost/function.hpp>
#include <boost/noncopyable.hpp>
#include <boost/algorithm/string.hpp>

#include <map>
#include <utility>
#include <set>
#include <string>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mysql.h>
#include <sys/resource.h>


#if BOOST_VERSION < 104700
namespace boost
{
  template <typename T>
    inline size_t hash_value(const boost::shared_ptr<T>& x)
    {
      return boost::hash_value(x.get());
    }
}
#endif



#define MSG_PENDING_MAX 65536
#define MSG_INVALID_RETURN "7e|04|000015|e7"

//#define DEBUG_MODE  //undef DEBUG_MODE for making debugPrint an empty statement

#define DEBUG_INVALID_MSG_INFORM //informing the client in concrete explanation when receiving an invalid but protocally correct message
#ifdef  DEBUG_MODE 
#define DEBUG_PRINT 1 //1:turn on printing in non-daemon
#else
#define DEBUG_PRINT 0
#endif


//hard codes below,may change in the future according to different format of protocol
#define MAX_MSG_LEN_BIT_NUM 6
#define COMPANY_CODE_PREFIX_LEN 5
#define MSG_CONSUMING_ITEMS_NUM_MIN 11
#define MSG_ITEMS_NUM_MIN  5
#define MSG_ITEMS_NUM_01 5
#define MSG_ITEMS_NUM_02 15
#define MSG_ITEMS_NUM_04 5
#define MSG_ITEMS_NUM_05 6
#define MSG_ITEMS_NUM_07 5
#define MSG_ITEMS_NUM_08 6



//when define a macro function,you must use "do{;}while(0)"!!!!
//https://onevcat.com/2014/01/black-magic-in-macro/

//the '##' token deals with something like 'debugprint("xxxx")',aka omitting comma after 'fmt'
//both fprintf() and fflush() is thread safe
#define debugPrint(fmt,...)\
  do{if(DEBUG_PRINT){fprintf(stdout,fmt,##__VA_ARGS__);\
      fflush(stdout);}}while(0) 

namespace dsrv
{
  using namespace std;
  using muduo::net::TcpServer;
  using muduo::net::TcpConnection;
  using muduo::net::TcpConnectionPtr;
  using muduo::net::EventLoop;
  using muduo::net::InetAddress;
  using muduo::net::Buffer;
  using muduo::MutexLock;
  using muduo::MutexLockGuard;
  using muduo::Timestamp;

  string utcToLocalTimeString(Timestamp utcTimestamp);
  string getLocalTimeString();//thread safe
  void asyncOutput(const char* msg, int len);
  
  typedef boost::weak_ptr<TcpConnection>WeakTcpConnectionPtr;
  struct Entry : public muduo::copyable
  {
    explicit Entry(const WeakTcpConnectionPtr& weakConn)
      : weakConn_(weakConn)
    {
    }

    ~Entry()
      {
	TcpConnectionPtr conn = weakConn_.lock();
	if (conn)
	  {
	    debugPrint("[%s,%s] WARN: time out\n",
		       getLocalTimeString().c_str(),
		       conn->peerAddress().toIpPort().c_str());
	    LOG_WARN<<"["<<getLocalTimeString()<<","
		    <<conn->peerAddress().toIpPort()
		    <<"] time out";
	    conn->forceClose();
	  }
      }

    WeakTcpConnectionPtr weakConn_;
  };
  struct MysqlConnInfo
  {
    string host;
    string user;
    string passwd;
    string db;
  MysqlConnInfo(string h,string u,string p,string d):host(h),user(u),passwd(p),db(d){}
  };
  typedef boost::shared_ptr<Entry> EntryPtr;
  typedef boost::weak_ptr<Entry> WeakEntryPtr;
  typedef boost::unordered_set<EntryPtr> Bucket;
  typedef boost::circular_buffer<Bucket> WeakConnectionList;
  typedef muduo::ThreadLocalSingleton<WeakConnectionList> LocalWeakConnectionList;
  typedef muduo::ThreadLocalSingleton<MYSQL>LocalMysqlConnection;

  class DemoServer
  {
  public:
    DemoServer(EventLoop* loop,InetAddress& listenAddr,
	       int numThreads,bool isAntiPiracy,
	       int idleSeconds,MysqlConnInfo mysqlConnInfo);
    void start();  // calls server_.start();
  private:
    void onConnection(const TcpConnectionPtr& conn);
    void onMessage(const TcpConnectionPtr& conn,Buffer* buf,Timestamp time);
    void onStringMessage(const TcpConnectionPtr& conn,const string& msg, const Timestamp& time);
    void processStringMessage(const TcpConnectionPtr& conn,const vector<string>& msgItems, const Timestamp& time,const string& oriMsg);
    string getInfoPrefix(const TcpConnectionPtr& conn);
    void forceCloseLog(const TcpConnectionPtr& conn,const string& logInfo,string msg);
    bool mysqlQueryWrap(MYSQL *mysql,const string& sqlStatement,const TcpConnectionPtr& conn,bool isRollback);
    void invalidInfoWarn(const TcpConnectionPtr& conn,const string& info);
    bool checkNumOfItems(const vector<string>&msgItems,const TcpConnectionPtr& conn,const string&msg);
    string setupMessage(const string&strMiddle,string cmd);
    bool processDAClientQuery(const TcpConnectionPtr& conn,const string& sep,const string& companyIDStr,const string& clientIDStr);
    void onTimer();
    void threadInit(EventLoop* loop);
    void addToUnauthorizedConns(const WeakTcpConnectionPtr& weakConn);//thread safe
    void unAuthorize(const WeakTcpConnectionPtr& weakConn);//thread safe
    bool authorize(const WeakTcpConnectionPtr& weakConn,int clientID);//thread safe
  
    bool isAntiPiracy_;
    int idleSeconds_;
    EventLoop* loop_;
    TcpServer server_;
    MutexLock mutex_;
    MutexLock mysqlInitMutex_;
    map<int,WeakTcpConnectionPtr>authorizedIDConn_;
    map<WeakTcpConnectionPtr,int>authorizedConnID_;
    set<WeakTcpConnectionPtr>unauthorizedConns_;
    MysqlConnInfo mysqlConnInfo_;
  
  };

  class MysqlRes
  {
  public:
    explicit MysqlRes(MYSQL * mysqlConn);
    ~MysqlRes();
    MysqlRes(const MysqlRes&)=delete;
    MysqlRes& operator=(const MysqlRes&)=delete;
    int numFields();
    MYSQL_ROW fetchRow();
    bool isValid();
  private:
    MYSQL_RES * result_;
  };










  
}



#endif
