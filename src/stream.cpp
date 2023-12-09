#include <algorithm>
#include <pcap/pcap.h>
#include "stream.h"
#include "dns.h"

using std::remove_if;

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
          auto ts = seconds{hdr.ts.tv_sec} + microseconds{hdr.ts.tv_usec};
          auto mts = std::chrono::duration_cast<milliseconds>(ts);
          if(q.query) {
	    if(q.type != DNS_TYPE_A) {
	      continue;
	    }
            stream_.push_back({mts, q.name});
	    fullstream_.push_back({mts, q.tid, true, q.name});
	  } else {
	    fullstream_.push_back({mts, q.tid, false, ""});
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


vector<string> stream::sequence(const set<string> association, string & when, int noise, int window)
{
  auto swindow = milliseconds(window + 200*(association.size() - 1));
  vector<dns_event_t> filtered;
  set<int> tids;
  for(auto m : fullstream_) {
    if(m.query) {
      if(association.find(m.host) == association.end()) {
        continue;
      }
      tids.insert(m.tid);
    }
    filtered.push_back(m);
  }

  for(auto it = filtered.begin(); it != filtered.end();) {
    if(!it->query && tids.find(it->tid) == tids.end()) {
      it = filtered.erase(it);
    } else {
      it++;
    }
  }
  
  if(filtered.empty()) {
    return vector<string>();
  }
  // slice long sequence
  // A    BCD     EAF    DXABC   A  C
  // 
  // to smaller sequences
  //
  // A
  // BCD
  // EAF
  // DXABC
  // A
  // C
  vector<vector<dns_event_t>> fragments;
  vector<dns_event_t> fragment;
  auto pts = filtered.begin()->ts;
  for(auto m : filtered) {
    if(m.ts - pts > swindow) {
      if(!fragment.empty()) {
        fragments.push_back(fragment);
	fragment.clear();
      }
    }
    fragment.push_back(m);
    pts = m.ts;
  }

  fragments.erase(remove_if(fragments.begin(), fragments.end(),
                            [](auto f) { 
			       return (f.size() < 2) || (f[0].tid != f[1].tid);
			    }),
		  fragments.end());

  for(auto & m : fragments) {
    m.erase(remove_if(m.begin(), m.end(), [](auto d) {return !d.query;}), m.end());
  }

  fragments.erase(remove_if(fragments.begin(), fragments.end(),
                            [association,noise](auto f) { 
			        set<string> uniques;
				for(auto e : f) {
				  uniques.insert(e.host);
				}
				return (uniques.size() < (association.size() - noise));
			    }), 
		  fragments.end());

  fragments.erase(remove_if(fragments.begin(), fragments.end(),
                            [](auto f) { 
			       return f.empty();
			    }),
		  fragments.end());

  vector<string> longest;
  for(auto m : fragments) {
    set<string> uniques;
    for(auto e : m) {
      uniques.insert(e.host);
    }
    if(uniques.size() <= longest.size()) {
      continue;
    }
    longest.clear();
    auto ts = m.begin()->ts;
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(ts);
    auto msecs = std::chrono::duration_cast<std::chrono::milliseconds>(ts - secs);
    // c++20
    //when = std::format("{}:{}", secs.count(), us.count());
    string second = std::to_string(secs.count());
    string msecond = std::to_string(msecs.count());
    when = second + ":" + msecond;
    for(auto e : m) {
      if(uniques.find(e.host) != uniques.end()) {
        longest.push_back(e.host);
	uniques.erase(e.host);
      }
    }
  }

  return longest;
}


} // end namespace dns

