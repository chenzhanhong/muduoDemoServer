

#include "DemoServer.h"

using namespace dsrv;

inline bool isInteger(const std::string & s)//thread safe
{
  if(s.empty() || ((!isdigit(s[0])) && (s[0] != '-') && (s[0] != '+'))) return false ;

  char * p ;
  strtol(s.c_str(), &p, 10) ;//thread safe

  return (*p == 0) ;
}

MysqlRes::MysqlRes(MYSQL* mysqlConn)
{
  result_=mysql_store_result(mysqlConn);
  if(result_==NULL)
    {
      string info="["+getLocalTimeString()+string("]")+" MYSQL ERROR: can not store results:"+
	string(mysql_error(mysqlConn));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
    }
}
MysqlRes::~MysqlRes()
{
  if(result_)
    {
      mysql_free_result(result_);
    }
  result_=NULL;
}

int MysqlRes::numFields()
{
  return mysql_num_fields(result_);
}

MYSQL_ROW MysqlRes::fetchRow()
{
  return mysql_fetch_row(result_);
}

bool MysqlRes::isValid()
{
  return (result_!=NULL);
}

void DemoServer::invalidInfoWarn(const TcpConnectionPtr& conn,const string& info)
 {
      debugPrint("%s\n",info.c_str());
      LOG_WARN<<info;
      //debugInformClient(info,conn);
#ifdef DEBUG_INVALID_MSG_INFORM
      conn->send(info);
#else
      conn->send(MSG_INVALID_RETURN);
#endif
 }

string DemoServer::setupMessage(const string&strMiddle,string cmd)
{
  string resMsg;
  string len=to_string(10+MAX_MSG_LEN_BIT_NUM+strMiddle.size());
  if(static_cast<int>(len.size())>MAX_MSG_LEN_BIT_NUM||static_cast<int>(cmd.size()!=2))
    {
      LOG_ERROR<<"invalid input for setupMessage()";
      return string(MSG_INVALID_RETURN);
    }
  string lenPadded=string(MAX_MSG_LEN_BIT_NUM-len.size(),'0')+len;
  resMsg="7e|"+cmd+"|"+lenPadded+"|"+strMiddle+"|e7";
  return resMsg;
}

bool DemoServer::mysqlQueryWrap(MYSQL *mysql,const string& sqlStatement,const TcpConnectionPtr& conn,bool isRollback)
{
  if(!mysql_query(mysql,sqlStatement.c_str()))
    {
      debugPrint("%s MYSQL INFO: affected %d rows\n",
		 getInfoPrefix(conn).c_str(),
		 static_cast<int>(mysql_affected_rows(mysql)));
    }
  else
    {
      if(mysql_errno(mysql)==2006)
	{
	  //conn->send("mysql server has gone away and reconnecting...");
	  mysql_ping(mysql);
	  mysql_query(mysql,sqlStatement.c_str());//restart the mysql_query after reconnecting
	}
      else
	{
	  string info=getInfoPrefix(conn)+" MYSQL ERROR:"
	    +string(mysql_error(mysql));
	  debugPrint("%s\n",info.c_str());
	  LOG_ERROR<<info;
	  
#ifdef DEBUG_INVALID_MSG_INFORM
	  conn->send(info);
#else
	  conn->send(MSG_INVALID_RETURN);
#endif
	  if(isRollback)
	    {
	      mysql_query(mysql,"ROLLBACK");
	    }
	     
	  return true;
		    
	}
    }
  return false;
}

string DemoServer::getInfoPrefix(const TcpConnectionPtr& conn)
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
      invalidInfoWarn(conn,info);
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
      invalidInfoWarn(conn,info);
      return;
    }

  //msgItems.size()>=MSG_ITEMS_NUM_MIN here and continue.
  string command=msgItems[1];
  if(command!="01"&&command!="02"&&command!="04"&&command!="05"&&command!="07"&&command!="08")
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: can not resolve command("+command+")";
      invalidInfoWarn(conn,info);
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
      invalidInfoWarn(conn,info);
      return;
    }

  string clientIDStr=msgItems[3];
  if(!isInteger(clientIDStr))
    {
      string info="["+getLocalTimeString()+","+
	conn->peerAddress().toIpPort()+
	"] WARN: clientID("+clientIDStr+") should be integer";
      invalidInfoWarn(conn,info);
      return;
    }

  int clientID=atoi(clientIDStr.c_str());
  if(!isAntiPiracy_||authorize(WeakTcpConnectionPtr(conn),clientID))
    {
      //process message here
      debugPrint("%s INFO processstringmessage(),with string:%s\n",
		 getInfoPrefix(conn).c_str(),msg.c_str());
      processStringMessage(conn,msgItems,time,msg);
    }
  
  
}//end of onStringmessage()

void DemoServer::processStringMessage(const TcpConnectionPtr& conn,const vector<string>& msgItems,
				      const Timestamp& time,const string& oriMsg)
{
  
  string command=msgItems[1];
  string clientIDStr=msgItems[3];
  string companyIDStr=clientIDStr.substr(0,COMPANY_CODE_PREFIX_LEN);
  string sep="','";
  int itemsLen=atoi(msgItems[2].c_str());
  if(command=="01")
    {
      //length check
      if(itemsLen!=1)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+") should be 1 (heart beat message:7e|01|1|clientID|e7)";
	  invalidInfoWarn(conn,info);
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
	  invalidInfoWarn(conn,info);
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
      
      sqlStatementConsumation="insert into demoOrder(ClientID,Date_time,Total_money,Status,Order_number,Pay_type,Currency, Member_number,Member_point,Membername,Memberpoint_sum)values('"+clientIDStr+sep+date+sep+totalMoney+sep+status+sep
	+orderNumber+sep+payType+sep+currency
	+sep+memberNumber+sep+memberPoint
	+sep+memberName+sep+memberPointSum+"')";
	
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"START TRANSACTION",conn,false)) return;

      string sqlStatementDAClients="SELECT DAClientID FROM demoDAClients where Company_code="+companyIDStr+" AND Isnew=0";
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementDAClients,conn,true)) return;

      //insert into demoCache
     
      MysqlRes resultDAClients(&LocalMysqlConnection::instance());
      string sqlStatementCache="INSERT INTO demoCache(DAClientID,Command,ToDelete) VALUES";
      int oriszCache=sqlStatementCache.size();
     
      if(resultDAClients.isValid())
	{

	  MYSQL_ROW row;
	  while((row=resultDAClients.fetchRow()))
	    {
	      string increment="('"+string(row[0])+sep+oriMsg+sep+string("0")+"'),";
	      sqlStatementCache+=increment;
	    }
	}
      if(static_cast<int>(sqlStatementCache.size())>oriszCache)
	{
	  sqlStatementCache.pop_back();
	  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementCache,conn,true)) return;
	}

      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementConsumation,conn,true)) return;
	
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
	      invalidInfoWarn(conn,info);
	      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"ROLLBACK",conn,false)) return;
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
	  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementOrderitem,conn,true)) return;
	}
      
      string consumingMsgRet=setupMessage(orderNumber,"02");
      conn->send(consumingMsgRet);
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"COMMIT",conn,false)) return;
    }
  else if(command=="04")
    {
      //length check
      if(itemsLen!=1)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 1 (adver (re)transmission request message:7e|04|1|clientID|e7)";
	  invalidInfoWarn(conn,info);
	  return;
	}
      //adver (re)transmission request message
      debugPrint("[%s,%s] INFO: adver (re)transmission request package received\n",
		 getLocalTimeString().c_str(),
		 conn->peerAddress().toIpPort().c_str());

      string sqlStatementAdver="SELECT ClientID,ID,Adname,URL,Date_start,Date_end FROM demoAdver where ClientID="+clientIDStr+" AND Isreturn=0";
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementAdver,conn,false)) return;
   
      MysqlRes resultAdver(&LocalMysqlConnection::instance());
     
      if(resultAdver.isValid())
	{
	  int fieldsNum=resultAdver.numFields();
	  MYSQL_ROW row;
	  row=resultAdver.fetchRow();
	  if(row)
	    {
	      string adverInfo;
	      for(int k=0;k<fieldsNum;++k)
		{
		  
		  adverInfo+=string((row[k]?row[k]:"NULL"));
		  adverInfo+="|";
		}
	      if(!adverInfo.empty())adverInfo.pop_back();
	      adverInfo=setupMessage(adverInfo,"03");
	      debugPrint("%s INFO: return adverInfo:%s",
			 getInfoPrefix(conn).c_str(),adverInfo.c_str());
	      conn->send(adverInfo);
	    }
	  else
	    {
	      debugPrint("%s INFO: there is no Adver for client %s to receive\n",
			 getInfoPrefix(conn).c_str() ,clientIDStr.c_str());
	    }

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
	  invalidInfoWarn(conn,info);
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
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementAdverIsreturnSet,conn,false)) return;
      //send next adver unreceived
      string adverInfo,sqlStatementAdver;
      debugPrint("%s INFO: gonna send another Adver unreceived\n",
		 getInfoPrefix(conn).c_str());
      sqlStatementAdver="SELECT ClientID,ID,Adname,URL,Date_start,Date_end FROM demoAdver where ClientID="+clientIDStr+" AND Isreturn=0";
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementAdver,conn,false)) return;
      
      MysqlRes resultAdver(&LocalMysqlConnection::instance());
      if(resultAdver.isValid())
	{
	  int fieldsNum=resultAdver.numFields();
	  MYSQL_ROW row;
	  row=resultAdver.fetchRow();
	  if(row)
	    {
	      string adverInfo;
	      for(int k=0;k<fieldsNum;++k)
		{
		 
		  adverInfo+=string((row[k]?row[k]:"NULL"));
		  adverInfo+="|";
		}
	      if(!adverInfo.empty())adverInfo.pop_back();
	      adverInfo=setupMessage(adverInfo,"03");
	      debugPrint("%s INFO: return adverInfo:%s",
			 getInfoPrefix(conn).c_str(),adverInfo.c_str());
	      conn->send(adverInfo);
	    }
	  else
	    {
	      debugPrint("%s INFO: there is no Adver for client %s to receive",
			 getInfoPrefix(conn).c_str() ,clientIDStr.c_str());
	    }
	 
	}
    }
  else if(command=="07")
    {
      if(itemsLen!=1)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 1 (loading consuming items message:7e|07|1|clientID|e7)";
	  invalidInfoWarn(conn,info);
	  return;
	}

      if(!processDAClientQuery(conn,sep,companyIDStr,clientIDStr))return;

    }//command=="07"

  else if(command=="08")
    {
      if(itemsLen!=2)
	{
	  string info=getInfoPrefix(conn)+" WARN: data length("+
	    msgItems[2]+
	    ") should be 2(loading consuming items message:7e|08|2|clientID|1or0|e7)";
	  invalidInfoWarn(conn,info);
	  return;
	}
      string isSuccess=msgItems[4];
      if(isSuccess=="0")
	{
	  //not success,retransmission
	  if(!processDAClientQuery(conn,sep,companyIDStr,clientIDStr))return;
	}
      else
	{
	   //delete from demoCache
	  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"START TRANSACTION",conn,false)) return;
	  string sqlStatementDeleteCache="DELETE FROM demoCache WHERE DAClientID="+clientIDStr+" AND Todelete=1";
	  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementDeleteCache,conn,true))return;
	  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"COMMIT",conn,false))return;
	}
     
      
    }
    
}//end of processstringmessage()

bool DemoServer::processDAClientQuery(const TcpConnectionPtr& conn,const string& sep,const string& companyIDStr,const string& clientIDStr)
{
  
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"START TRANSACTION",conn,false)) return false;
      
      string sqlStatementDAClients="SELECT Isnew FROM demoDAClients WHERE DAClientID="+clientIDStr;
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementDAClients,conn,true))return false;
      MysqlRes resultDAClients(&LocalMysqlConnection::instance());
      if(resultDAClients.isValid())
	{
	  MYSQL_ROW row=resultDAClients.fetchRow();
	  if(row)
	    {
	      int isNew=stoi(string(row[0]));
	      if(isNew==1)
		{
		  //a new DAClient
		  string sqlStatementOrder="SELECT ID,ClientID,Date_time,Total_money,Status,Order_number,Pay_type,Currency, Member_number,Member_point,Membername,Memberpoint_sum FROM demoOrder WHERE LEFT(ClientID,"+to_string(COMPANY_CODE_PREFIX_LEN)+")="+companyIDStr;
		  string ID,ClientID,Date_time,Total_money,Status,Order_number,Pay_type,Currency, Member_number,Member_point,Membername,Memberpoint_sum;
		  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementOrder,conn,true))return false;
		  MysqlRes resultOrder(&LocalMysqlConnection::instance());
		  if(resultOrder.isValid())
		    {
		      
		      MYSQL_ROW row;
		      while((row=resultOrder.fetchRow()))
			{
			  ID=string(row[0]);
			  ClientID=string(row[1]);
			  Date_time=string(row[2]);
			  Total_money=string(row[3]);
			  Status=string(row[4]);
			  Order_number=string(row[5]);
			  Pay_type=string(row[6]);
			  Currency=string(row[7]);
			  Member_number=string(row[8]);
			  Member_point=string(row[9]);
			  Membername=string(row[10]);
			  Memberpoint_sum=string(row[11]);
			  string pre=ClientID+'|'+Date_time+'|'+Total_money+'|'+Status+'|'+Pay_type+'|'+Order_number+'|'+Currency+'|'+Member_number+'|'+Member_point+'|'+Membername+'|'+Memberpoint_sum;
			  string sqlStatementOrderitem="SELECT Name,Number FROM demoOrderitem WHERE OrderID="+ID;
			  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementOrderitem,conn,true))return false;
			  MysqlRes resultOrderitem(&LocalMysqlConnection::instance());
			  if(resultOrderitem.isValid())
			    {
			      MYSQL_ROW row2;
			      bool notEmpty=false;
			      while((row2=resultOrderitem.fetchRow()))
				{
				  notEmpty=true;
				  pre+='|';
				  pre+=string(row2[0]);
				  pre+=',';
				  pre+=string(row2[1]);
				}
			      if(notEmpty)
				{
				  //restore the consuming message
				  string Command=setupMessage(pre,"02");
				  string sqlStatementInsertCache="INSERT INTO demoCache(DAClientID,Command,ToDelete) VALUES";
				  string increment="('"+clientIDStr+sep+Command+sep+string("0")+"')";
				  sqlStatementInsertCache+=increment;
				  if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementInsertCache,conn,true))return false;
				    
				}
			    }
						   
			}
		     
		    }
		   string sqlStatementUpdateDAClients="UPDATE demoDAClients SET Isnew=0 WHERE DAClientID="+clientIDStr;
		   if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementUpdateDAClients,conn,true))return false;
		}
	      //ClientID is not new from below;
              string sqlStatementSelectCache="SELECT Command FROM demoCache WHERE DAClientID="+clientIDStr;
	      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementSelectCache,conn,true))return false;
	      MysqlRes resultSelectCache(&LocalMysqlConnection::instance());
	      if(resultSelectCache.isValid())
		{
		  MYSQL_ROW row3;
		  while((row3=resultSelectCache.fetchRow()))
		    {
		      conn->send(setupMessage(string(row3[0]),"07"));
		    }
		}
	      //set toDelete
	      string sqlStatementUpdateCache="UPDATE demoCache SET ToDelete=1 WHERE DAClientID="+clientIDStr;
	      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),sqlStatementUpdateCache,conn,true))return false;
	    }

	  //ClientID is not in table demoDAClients from below;
	}
      // sending a message to client when done
      conn->send(setupMessage("1","08"));
      
      if(mysqlQueryWrap(&LocalMysqlConnection::instance(),"COMMIT",conn,false))return false;
      return true;
}
