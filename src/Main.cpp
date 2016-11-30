#include "DemoServer.h"
using namespace std;

int main(int argc, char* argv[])
{

  //run as a daemon
  //if(daemon(1,0)==-1)//DO NOT change the process's current working directory!aka daemon(0,0) is prohibited!
  //{
  // LOG_FATAL<<"daemon()";
  // }
  
  //logging bussiness in one thread!
  extern muduo::AsyncLogging* g_asyncLog;
  
  {
    // set max virtual memory to 2GB.
    size_t kOneGB = 1000*1024*1024;
    rlimit rl = { 2*kOneGB, 2*kOneGB };
    setrlimit(RLIMIT_AS, &rl);
  }
  
  char name[256];
  strncpy(name, argv[0], 256);
  int kRollSize = 500*1000*1000;
  muduo::AsyncLogging log(::basename(name), kRollSize);
  log.start();
  g_asyncLog = &log;
  muduo::Logger::setOutput(dsrv::asyncOutput);
  muduo::Logger::setLogLevel(muduo::Logger::LogLevel::WARN);

  if(mysql_thread_safe())
    {
      debugPrint("the mysql client library is thread safe\n");
    }
  else
    {
      LOG_FATAL<<"the mysql client library is NOT thread safe";
    }
 
  if(mysql_library_init(0,NULL,NULL))//mysql_library_init() is not thread safe,call it prior to spawning any threads;
    {
      LOG_FATAL<<"could not initialize mysql library";
    }
  //our anti-piracy strategy handles "one clientID with one connection" situation.It is UNDEFINED in other situations!
  bool isAntiPiracy=true;
  int numThreads=3;
  int idleSeconds=3600;
  LOG_INFO << "pid = " << getpid();
  muduo::net::EventLoop loop;
  muduo::net::InetAddress listenAddr(2007);
  dsrv::MysqlConnInfo mysqlConnInfo("localhost","root","cita109109","demoDB");
  
  dsrv::DemoServer server(&loop, listenAddr,numThreads,isAntiPiracy,idleSeconds,mysqlConnInfo);
  server.start();
  loop.loop();

  mysql_library_end();//good pratice anyway.
}
