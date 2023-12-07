#include <algorithm>
#include <pcap/pcap.h>
#include "stream.h"
#include "dns.h"

namespace dns {

stream::stream(const string file)
	: file_(file), loaded_(false), errcode_(0)
{
  tload_ = std::thread([this]
  {
    char errmsg[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(file_.c_str(), errmsg); 
    if(pcap == NULL) {
      errcode_ = -1;
      errmsg_ = errmsg;
    } else {
      const uint8_t *packet;
      struct pcap_pkthdr hdr;
      while((packet = pcap_next(pcap, &hdr)) != NULL) {
        struct question q;
        if(dns_parse(packet, &q) == 0) {
          if(q.query && q.type == DNS_TYPE_A) {
            auto ts = seconds{hdr.ts.tv_sec} + microseconds{hdr.ts.tv_usec};
            auto mts = std::chrono::duration_cast<milliseconds>(ts);
            stream_.push_back({mts, q.name});
	  }
        }
      }
      errcode_ = 0;
      errmsg_ = "";
    }

    {
      std::lock_guard lk(mtx_);
      loaded_= true;
    }
    cv_.notify_one();
  });
}

stream::~stream()
{
  if(tload_.joinable()) {
    tload_.join();
  }
}

string stream::id()
{
  return file_;
}

int stream::load(string & errmsg)
{
  std::unique_lock lk(mtx_);
  cv_.wait(lk, [this]{ return loaded_; });

  if(errcode_ != 0 ) {
    errmsg = errmsg_;
    return errcode_;
  }

  return 0;
}

int stream::volume()
{
  return stream_.size();
}

set<string> stream::space()
{
  set<string> ret;
  for(auto m : stream_) {
    ret.insert(m.host);
  }

  return ret;
}

map<string, int> stream::histro()
{
  map<string, int> ret;
  for(auto m : stream_) {
    ret[m.host]++;
  }

  return ret;

}

bool stream::contains(const string host)
{
  auto hosts = space();
  return hosts.find(host) != hosts.end();
}

bool stream::contains(const set<string> group)
{
  for(auto m : group) {
    if(!contains(m)) {
      return false;
    }
  }

  return true;
}

set<string> stream::window(milliseconds start, milliseconds end) const
{
  set<string> ret;
  std::for_each(stream_.begin(), stream_.end(), [&ret, start, end](auto dns) {
		    if(dns.ts > start && dns.ts < end) {
		      ret.insert(dns.host);
		    }
		  });
  return ret;
}

vector<set<string>> stream::adjacent(const string host, int milli) const
{
  vector<set<string>> adjacent;
  for(auto m: stream_) {
    if(m.host == host) {
      auto start = m.ts - milliseconds(milli);
      auto end = m.ts + milliseconds(milli);
      adjacent.push_back(window(start, end));
    } 
  }
  return adjacent;
}

vector<set<string>> stream::adjacent_backward(const string host, int milli)
{
  vector<set<string>> adjacent;
  return adjacent;
}

vector<set<string>> stream::adjacent_forward(const string host, int milli)
{
  vector<set<string>> adjacent;
  return adjacent;
}


}

