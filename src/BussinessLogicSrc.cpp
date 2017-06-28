
#include "DemoServer.h"

using namespace dsrv;

inline bool isInteger(const std::string & s)//thread safe
{
  if(s.empty() || ((!isdigit(s[0])) && (s[0] != '-') && (s[0] != '+'))) return false ;

  char * p ;
  strtol(s.c_str(), &p, 10) ;//thread safe

  return (*p == 0) ;
}

inline string getInfoPrefix(const TcpConnectionPtr& conn)
{
  string infoPrefix="["+getLocalTimeString()+","
    +conn->peerAddress().toIpPort()+"]";
  return infoPrefix;
}

void DemoServer::onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp time)
{
  //It is essential to process the message buffer on user application layer because TCP is based on borderless byte stream.
  //We need to seperate protocally correct messages("7e|*****|e7") from the buffer.
  //A protocally correct message is picked up and then analyzed on onStringMessage().
  //Incorrect message is discarded and the connection would be removed by the server.Considering that TCP is reliable,a header or tail missing indicates that the client is unaware with our mechanisim and would not be deemed as a target client.
  //Message would pend on the buffer when a "7e|" occured and "|e7" not yet.However ,when the buffer readableBytes reaches our limitation the corresponding connection would be closed for fear that a malicious client runs out of our memory.


  debugPrint("%s INFO: onMessage() called,with pending string:%s\n",getInfoPrefix(conn).c_str(),string(buf->peek(),buf->readableBytes()).c_str());
  
  //update the timing wheel
  WeakEntryPtr weakEntry(boost::any_cast<WeakEntryPtr>(conn->getContext()));
  EntryPtr entry(weakEntry.lock());
  if (entry)
    {
      LocalWeakConnectionList::instance().back().insert(entry);
    }  

  //handles readable bytes less than 3 
  int bytesNum=buf->readableBytes();
  string header;
  switch(bytesNum)
    {
    case 1:
      {
	header=string(buf->peek(),1);
	if(header!="7")
	  {
	    
	    debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
		       getLocalTimeString().c_str(),
		       conn->peerAddress().toIpPort().c_str(),
		       header.c_str());
	    LOG_WARN<<"["<<getLocalTimeString()<<","
		    <<conn->peerAddress().toIpPort()
		    <<"] NOT protocally correct message";
	    //buf->retrieve(1);
	    conn->forceClose();
	    return;
	  }
	return;
      }
    case 2:
      {
	header=string(buf->peek(),2);
	if(header!="7e")
	  {
	    
	    debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
		       getLocalTimeString().c_str(),
		       conn->peerAddress().toIpPort().c_str(),
		       header.c_str());
	    LOG_WARN<<"["<<getLocalTimeString()<<","
		    <<conn->peerAddress().toIpPort()
		    <<"] NOT protocally correct message";
	    //buf->retrieve(2);
	    conn->forceClose();
	    return;
	  }
	return;
      }
    default:
      {
	break;
      }
	
    }
  
  //handles with readableBytes >=3
  string totalMsg(buf->peek(),buf->readableBytes());
  string str;
  bool isHeaderFound=false;
  size_t posPeek=0;
  size_t posCurHead=0;
  size_t posCurEnd=0;
  for(size_t i=0;i<totalMsg.size();++i)
    {
      if(!isHeaderFound)
	{
	  posCurHead=totalMsg.find("7e|",i);
	  if(posCurHead==string::npos)
	    {
	      if(totalMsg.substr(totalMsg.size()-1)=="7")
		{
		  if(buf->readableBytes()-1!=0)
		    {
		      
		      debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
				 getLocalTimeString().c_str(),
				 conn->peerAddress().toIpPort().c_str(),
				 string(buf->peek(),
					buf->readableBytes()-1).c_str());
		      LOG_WARN<<"["<<getLocalTimeString()<<","
			      <<conn->peerAddress().toIpPort()
			      <<"] NOT protocally correct message";
		      //buf->retrieve(buf->readableBytes()-1);
		      conn->forceClose();
		      return;
		    }
		}
	      else if(totalMsg.substr(totalMsg.size()-2)=="7e")
		{
		  if(buf->readableBytes()-2!=0)
		    {
		     
		      debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
				 getLocalTimeString().c_str(),
				 conn->peerAddress().toIpPort().c_str(),
				 string(buf->peek(),
					buf->readableBytes()-2).c_str());
		      LOG_WARN<<"["<<getLocalTimeString()<<","
			      <<conn->peerAddress().toIpPort()
			      <<"] NOT protocally correct message";
		      buf->retrieve(buf->readableBytes()-2);
		      conn->forceClose();
		      return;
		    }
		}
	      else
		{
		  debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
			     getLocalTimeString().c_str(),
			     conn->peerAddress().toIpPort().c_str(),
			     (buf->retrieveAllAsString()).c_str());
		  LOG_WARN<<"["<<getLocalTimeString()<<","
			  <<conn->peerAddress().toIpPort()
			  <<"] NOT protocally correct message";
		  conn->forceClose();
		  return;
		}
	      if(buf->readableBytes()>MSG_PENDING_MAX)
		{
		  debugPrint("[%s,%s] WARN: pending buffer may overflow\n",
			     getLocalTimeString().c_str(),
			     conn->peerAddress().
			     toIpPort().c_str());
		  LOG_WARN<<"["<<getLocalTimeString()<<","
			  <<conn->peerAddress().toIpPort()
			  <<"] pending buffer may overflow";
		  conn->forceClose();
		  return;
		}
	      return;
	    }
	  else
	    {
	      isHeaderFound=true;
	      i=posCurHead+2;
	      if(posCurHead>posPeek)
		{
		 
		  debugPrint("[%s,%s] WARN: NOT protocally correct message:%s\n",
			     getLocalTimeString().c_str(),
			     conn->peerAddress().toIpPort().c_str(),
			     string(buf->peek(),posCurHead-posPeek).c_str());
		  LOG_WARN<<"["<<getLocalTimeString()<<","
			  <<conn->peerAddress().toIpPort()
			  <<"] NOT protocally correct message";
		  conn->forceClose();
		  return;
		  //buf->retrieve(posCurHead-posPeek);
		  //posPeek=posCurHead;
		}
	    }
	}
      else
	{
	  posCurEnd=totalMsg.find("|e7",i);
	  if(posCurEnd==string::npos)
	    {
	      
	      if(buf->readableBytes()>MSG_PENDING_MAX)
		{
		  debugPrint("[%s,%s] WARN: pending buffer may overflow\n",
			     getLocalTimeString().c_str(),
			     conn->peerAddress().toIpPort().c_str());
		  LOG_WARN<<"["<<getLocalTimeString()<<","
			  <<conn->peerAddress().toIpPort()
			  <<"] pending buffer may overflow";
		  conn->forceClose();
		  return;
		}
	      return;
	    }
	  else
	    {
	      isHeaderFound=false;
	      i=posCurEnd+2;
	      str=string(buf->peek(),posCurEnd-posCurHead+3);
	      buf->retrieve(posCurEnd-posCurHead+3);
	      posPeek=posCurEnd+3;
	      onStringMessage(conn,str,time);
	    }
	}
    }

  if(buf->readableBytes()>MSG_PENDING_MAX)
    {
      debugPrint("[%s,%s] WARN: pending buffer may overflow\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());
      LOG_WARN<<"["<<getLocalTimeString()<<","
	      <<conn->peerAddress().toIpPort()
	      <<"] pending buffer may overflow";
      conn->forceClose();
      return;
    }
  return;
}

void DemoServer::onStringMessage(const TcpConnectionPtr& conn,
				 const string& msg, const Timestamp& time)
{
  
  debugPrint("[%s,%s] INFO: onStringMessage() called,receive a message:%s\n",
	     getLocalTimeString().c_str(),
	     conn->peerAddress().toIpPort().c_str(),
	     msg.c_str());
  
  if(msg.size()<MSG_LENGTH_MIN)
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: total number of bytes("+
	to_string(msg.size())+
	") in a message should not less than "+
	to_string(MSG_LENGTH_MIN);
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
      return;
    }
  
  vector<string>msgItems;
  boost::split(msgItems,msg,boost::is_any_of("|"));

  if(msgItems.size()<MSG_ITEMS_NUM_MIN)
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: total number of items("+to_string(msgItems.size())+
	") in a message should not less than "+
	to_string(MSG_ITEMS_NUM_MIN);
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
      return;
    }

  //msgItems.size()>=MSG_ITEMS_NUM_MIN here and continue.
  string command=msgItems[1];
  if(command!="01"&&command!="02"&&command!="04"&&command!="05"&&command!="06")
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: can not resolve command("+command+")";
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
      return;
    }

  string validItemsLen=msgItems[2];
  if(!isInteger(validItemsLen)||
     atoi(validItemsLen.c_str())!=static_cast<int>(msgItems.size())-4)
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: data length("+validItemsLen+
	") do not equal to the actual("+
	to_string(msgItems.size()-4)+")";
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
      return;
    }

  string clientIDStr=msgItems[3];
  if(!isInteger(clientIDStr))
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: clientID("+clientIDStr+") should be integer";
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
      return;
    }

  int clientID=atoi(clientIDStr.c_str());
  if(!isAntiPiracy_||authorize(WeakTcpConnectionPtr(conn),clientID))
    {
      //process message here
      debugPrint("%s INFO processstringmessage(),with string:%s\n",
		 getInfoPrefix(conn).c_str(),msg.c_str());
      processStringMessage(conn,msgItems,time);
    }
  
  
}//end of onStringmessage()

void DemoServer::processStringMessage(const TcpConnectionPtr& conn,const vector<string>& msgItems, const Timestamp& time)
{
  
  string command=msgItems[1];
  string clientIDStr=msgItems[3];
  int itemsLen=atoi(msgItems[2].c_str());
  if(command=="01")
    {
      //length check
      if(itemsLen!=1)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+") should be 1 (heart beat message:7e|01|1|clientID|e7)";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
	  //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //heart beat message
      debugPrint("[%s,%s] INFO: heartbeat package received\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());
    }
  else if(command=="02")
    {
      //length check
      if(atoi(msgItems[2].c_str())<MSG_CONSUMING_ITEMS_NUM_MIN)
	{
	  string info=getInfoPrefix(conn)+" WARN: consuming items loss";
	  debugPrint("%s\n",info.c_str());
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //consuming message
      debugPrint("[%s,%s] INFO: consuming package received\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());
     
      string date,totalMoney,status,orderNumber,payType,currency,memberNumber,
	memberPoint,memberName,memberPointSum;
      date=msgItems[4];
      totalMoney=msgItems[5];
      status=msgItems[6];
      payType=msgItems[7];
      orderNumber=msgItems[8];
      currency=msgItems[9];
      memberNumber=msgItems[10];
      memberPoint=msgItems[11];
      memberName=msgItems[12];
      memberPointSum=msgItems[13];
      string sqlStatementConsumation;
      string sep="','";
      sqlStatementConsumation="insert into demoOrder(ClientID,Date_time,Total_money,Status,Order_number,Pay_type,Currency, Member_number,Member_point,Membername,Memberpoint_sum)values('"+clientIDStr+sep+date+sep+totalMoney+sep+status+sep
	+orderNumber+sep+payType+sep+currency
	+sep+memberNumber+sep+memberPoint
	+sep+memberName+sep+memberPointSum+"')";
      //mysql_ping(&LocalMysqlConnection::instance());
      if(mysql_query(&LocalMysqlConnection::instance(),"START TRANSACTION"))
	{
	  if(mysql_errno(&LocalMysqlConnection::instance())==2006)
	    {
	      conn->send("mysql server has gone away and reconnecting...");
	      mysql_ping(&LocalMysqlConnection::instance());
	      mysql_query(&LocalMysqlConnection::instance(),"START TRANSACTION");//restart the mysql_query after reconnecting
	    }
	  else
	    {
	      string info=getInfoPrefix(conn)+" MYSQL ERROR:inserted error:"
		+string(mysql_error(&LocalMysqlConnection::instance()));
	      debugPrint("%s\n",info.c_str());
	      LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	      conn->send(info);
#else
	      conn->send(MSG_INVALID_RETURN);
#endif
	      return;
	    }
	}
      if(!mysql_query(&LocalMysqlConnection::instance(),sqlStatementConsumation.c_str()))
	{
	  debugPrint("%s MYSQL INFO: inserted %lu rows\n",
		     getInfoPrefix(conn).c_str(),
		     static_cast<unsigned long>(mysql_affected_rows(&LocalMysqlConnection::instance())));
	}
      else
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:inserted error:"
	    +string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  mysql_query(&LocalMysqlConnection::instance(),"ROLLBACK");
	  return;
	}

      string orderIDStr=to_string(mysql_insert_id(&LocalMysqlConnection::instance()));
      string sqlStatementOrderitem="insert into demoOrderitem(OrderID,Name,Number) values";
      int orisz=sqlStatementOrderitem.size();
      for(size_t i=3+MSG_CONSUMING_ITEMS_NUM_MIN;i<=msgItems.size()-2;++i)
	{
	  vector<string>commodity;
    	  boost::split(commodity,msgItems[i],boost::is_any_of(","));
	  if(commodity.size()!=2)
	    {
	      string info=getInfoPrefix(conn)+
		" WARN: each sales item should include two parts";
	      debugPrint("%s\n",info.c_str());
	      LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	      conn->send(info);
#else
	      conn->send(MSG_INVALID_RETURN);
#endif
	      mysql_query(&LocalMysqlConnection::instance(),"ROLLBACK");
	      return;
	    }
	  else
	    {
	      string commodityName=commodity[0];
	      string commodityNum=commodity[1];
	      string increment="('"+orderIDStr+sep+commodityName+sep+commodityNum+"'),";
	      sqlStatementOrderitem+=increment;
	      
	    }
	}

      if(static_cast<int>(sqlStatementOrderitem.size())>orisz)
	{
	  //batch insertion for optimization
	  sqlStatementOrderitem.pop_back();//remove last character ','
	  if(!mysql_query(&LocalMysqlConnection::instance(),sqlStatementOrderitem.c_str()))
	    {
	      debugPrint("%s MYSQL INFO: inserted %lu rows\n",
			 getInfoPrefix(conn).c_str(),
			 static_cast<unsigned long>(mysql_affected_rows(&LocalMysqlConnection::instance())));
	    }
	  else
	    {
	      string info=getInfoPrefix(conn)+" MYSQL ERROR:inserted error:"
		+string(mysql_error(&LocalMysqlConnection::instance()));
	      debugPrint("%s\n",info.c_str());
	      LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	      conn->send(info);
#else
	      conn->send(MSG_INVALID_RETURN);
#endif
	      mysql_query(&LocalMysqlConnection::instance(),"ROLLBACK");
	      return;
	    }
	}
      
      string consumingMsgRet="7e|02|"+orderNumber+"|e7";
      conn->send(consumingMsgRet);
      mysql_query(&LocalMysqlConnection::instance(),"COMMIT");
    }
  else if(command=="04")
    {
      //length check
      if(itemsLen!=1)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 1 (adver (re)transmission request message:7e|04|1|clientID|e7)";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //adver (re)transmission request message
      debugPrint("[%s,%s] INFO: adver (re)transmission request package received\n",
	         getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());

      string sqlStatementAdver="SELECT ClientID,ID,Adname,URL,Date_start,Date_end FROM demoAdver where ClientID="+clientIDStr+" AND Isreturn=0";
      if(mysql_query(&LocalMysqlConnection::instance(),sqlStatementAdver.c_str()))
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:demoAdver select error:"
	    +string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;	  
	}

      MYSQL_RES *result = mysql_store_result(&LocalMysqlConnection::instance());
      if(result==NULL)
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR: can not store results:"+
	    string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	}
      else
	{
	  int fieldsNum=mysql_num_fields(result);
	  MYSQL_ROW row;
	  row=mysql_fetch_row(result);
	  if(row)
	    {
	      string adverInfo="7e|03|6";
	      for(int k=0;k<fieldsNum;++k)
		{
		  adverInfo+="|";
		  adverInfo+=string((row[k]?row[k]:"NULL"));
		}
	      adverInfo+="|e7";
	      debugPrint("%s INFO: return adverInfo:%s",
			 getInfoPrefix(conn).c_str(),adverInfo.c_str());
	      conn->send(adverInfo);
	    }
	  else
	    {
	      debugPrint("%s INFO: there is no Adver for client %s to receive\n",
			 getInfoPrefix(conn).c_str() ,clientIDStr.c_str());
	    }
	  mysql_free_result(result);
	}
	    
    }
  else if(command=="05")
    {
      //length check
      if(itemsLen!=2)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 2 (adver confirmation return message:7e|05|2|clientID|adverID|e7)";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //adver confirmation return message
      debugPrint("[%s,%s] INFO: adver confirmation return package received\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());

      string sqlStatementAdverIsreturnSet,adIDStr;
      adIDStr=msgItems[4];
      sqlStatementAdverIsreturnSet="UPDATE demoAdver SET Isreturn='1' WHERE ID="
	+adIDStr;
      mysql_ping(&LocalMysqlConnection::instance());
      if(!mysql_query(&LocalMysqlConnection::instance(),sqlStatementAdverIsreturnSet.c_str()))
	{
	  debugPrint("%s Update %lu rows\n",getInfoPrefix(conn).c_str(),
		     static_cast<unsigned long>(mysql_affected_rows(&LocalMysqlConnection::instance())));
	}
      else
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR: mysql update error:"+
	    string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //send next adver unreceived
      string adverInfo,sqlStatementAdver;
      debugPrint("%s INFO: gonna send another Adver unreceived\n",
		 getInfoPrefix(conn).c_str());
      sqlStatementAdver="SELECT ClientID,ID,Adname,URL,Date_start,Date_end FROM demoAdver where ClientID="+clientIDStr+" AND Isreturn=0";
      mysql_ping(&LocalMysqlConnection::instance());
      if(mysql_query(&LocalMysqlConnection::instance(),sqlStatementAdver.c_str()))
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:demoAdver select error:"
	    +string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;	  
	}
      
      MYSQL_RES *result = mysql_store_result(&LocalMysqlConnection::instance());
      if(result==NULL)
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR: can not store results:"+
	    string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	}
      else
	{
	  int fieldsNum=mysql_num_fields(result);
	  MYSQL_ROW row;
	  row=mysql_fetch_row(result);
	  if(row)
	    {
	      string adverInfo="7e|03|6";
	      for(int k=0;k<fieldsNum;++k)
		{
		  adverInfo+="|";
		  adverInfo+=string((row[k]?row[k]:"NULL"));
		}
	      adverInfo+="|e7";
	      debugPrint("%s INFO: return adverInfo:%s",
			 getInfoPrefix(conn).c_str(),adverInfo.c_str());
	      conn->send(adverInfo);
	    }
	  else
	    {
	      debugPrint("%s INFO: there is no Adver for client %s to receive",
			 getInfoPrefix(conn).c_str() ,clientIDStr.c_str());
	    }
	  mysql_free_result(result);
	}
    }
  else if(command=="06")
    {
      //length check
      if(itemsLen!=3)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 3";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      //data query request
      debugPrint("[%s,%s] INFO: data query request package received\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());
      string sqlStatementClientQuery,sqlStatementProductQuery;
      vector<string>times;
      boost::split(times,msgItems[4],boost::is_any_of(","));
      if(times.size()!=2)
	{
	  string info=getInfoPrefix(conn)+
	    " WARN: |start date,end date| is needed!The other format is invalid.";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      string start_date="'"+times[0]+"'",end_date="'"+times[1]+"'";
      vector<string>clients;
      boost::split(clients,msgItems[5],boost::is_any_of(","));
      if(clients.empty())
	{
	  string info=getInfoPrefix(conn)+
	    " WARN: empty clients set for querying.";
	  debugPrint("%s\n",info.c_str());
	  LOG_WARN<<info;
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;
	}
      string clientsStr="(";
      for(auto&client:clients)
	{
	  clientsStr+="'";
	  clientsStr+=client;
	  clientsStr+="'";
	  clientsStr+=",";
	}
      clientsStr[clientsStr.size()-1]=')';
      sqlStatementProductQuery="select i.name,sum(i.number) as product_num from demoOrder as o,demoOrderitem as i where (o.ID=i.orderID) and (o.clientID in "+clientsStr+") and (date(o.date_time) between "+start_date+" and "+end_date+") group by i.name order by product_num desc";
      sqlStatementClientQuery="select clientID,count(*) as order_num,sum(total_money) as order_total_money from demoOrder where (clientID in "+clientsStr+") and (date(date_time) between "+start_date+" and "+end_date+") group by clientID order by order_total_money desc";
      mysql_ping(&LocalMysqlConnection::instance());
      if(mysql_query(&LocalMysqlConnection::instance(),sqlStatementProductQuery.c_str()))
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:select error in product query:"
	    +string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;	  
	}
      string query_ret="7e|06|";
      MYSQL_RES *result_product = mysql_store_result(&LocalMysqlConnection::instance());
      if(result_product==NULL)
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR: can not store results:"+
	    string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	}
      else
	{
	  MYSQL_ROW row;
	  string item_result_product;
	  while ((row = mysql_fetch_row(result_product)))
	    {
	      string curRow=string(row[0])+"!"+string(row[1]);
	      item_result_product+=curRow;
	      item_result_product+=",";
	    }
	  if(!item_result_product.empty())
	    item_result_product[item_result_product.size()-1]='|';
	  else
	    item_result_product="|";
	  query_ret+=item_result_product;
	  mysql_free_result(result_product);
	}

      if(mysql_query(&LocalMysqlConnection::instance(),sqlStatementClientQuery.c_str()))
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:select error in client query:"
	    +string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  return;	  
	}

      MYSQL_RES *result_client = mysql_store_result(&LocalMysqlConnection::instance());
      if(result_client==NULL)
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR: can not store results:"+
	    string(mysql_error(&LocalMysqlConnection::instance()));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	}
      else
	{
	  MYSQL_ROW row;
	  string item_result_client;
	  while ((row = mysql_fetch_row(result_client)))
	    {
	      string curRow=string(row[0])+"!"+string(row[1])+"!"+string(row[2]);
	      item_result_client+=curRow;
	      item_result_client+=",";
	    }
	  if(!item_result_client.empty())
	    item_result_client[item_result_client.size()-1]='|';
	  else
	    item_result_client="|";
	  query_ret+=item_result_client;
	  mysql_free_result(result_client);
	}
      query_ret+="e7";
      conn->send(query_ret);
    }

}//end of processstringmessage()
