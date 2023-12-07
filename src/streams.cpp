#include <algorithm>
#include "streams.h"

namespace dns {
namespace streams {

int volume(const streams_t & ss)
{
  int ret = 0;
  for(auto s : ss) {
    ret += s->volume();
  }
  return ret;
}

set<string> space(const streams_t & ss)
{
  set<string> ret;
  for(auto s : ss) {
    auto onespace = s->space();
    for(auto m : onespace) {
      ret.insert(m);//c++17 provides merge method
    } 
  }
  return ret;
}

vector<pair<string, int>> histro(const streams_t & ss, int threshold)
{
  map<string, int> raw;
  for(auto s : ss) {
    auto one = s->histro();
    for(auto m : one) {
      raw[m.first] += m.second;
    }
  }

  // filter
  if(threshold > 1) {
    for(auto it = raw.begin(); it != raw.end();) {
      if(it->second < threshold) {
        it = raw.erase(it);
      } else {
        ++it;
      }
    }
  }

  //sort
  vector<pair<string, int>> ret;
  for(auto m : raw) {
    ret.push_back({m.first, m.second});
  }
  std::sort(ret.begin(), ret.end(), [] (auto l, auto r) {
		  return l.second > r.second; 
           });
 
  return ret;
}

vector<pair<string, int>> conditional(const streams_t & ss, const string host, int window)
{
  vector<pair<string, int>> ret;

  // element of the vector means:
  // neighbors of the host, in one occurrence
  vector<set<string>> raw;

  for(auto s : ss) {
    auto one = s->adjacent(host, window); //search in one stream
    std::move(one.begin(), one.end(), std::back_inserter(raw)); //merge streams
  }

  // statistic of neighbors
  map<string, int> histro;
  for(auto m : raw) {
    for(auto e : m) {
      histro[e]++;
    }
  }

  // sort
  int x = histro[host];
  histro.erase(host);
  for(auto m : histro) {
    ret.push_back({m.first, m.second});
  }
  std::sort(ret.begin(), ret.end(), [] (auto l, auto r) {
		  return l.second > r.second; 
           });
  ret.insert(ret.begin(), {host, x});

  return ret;
}

map<string, vector<pair<string, int>>> conditional(const streams_t & ss, int threshold, int window)
{
  map<string, vector<pair<string, int>>> ret;

  auto h = histro(ss, threshold);
  for(auto e: h) {
    ret[e.first] = conditional(ss, e.first, window);
  }

  return ret;
}

set<string> association(const map<string, vector<pair<string, int>>> & cdb, const string host, double threshold)
{
  set<string> ret;
  for(auto m : cdb) {
    if(m.first == host) {
      int total = m.second.begin()->second;
      for(auto e: m.second) {
	if((double)e.second/total > threshold)
          ret.insert(e.first);
      }
      continue;
    }
    for(auto e : m.second) {
      if(e.first == host) {
        int total = m.second.begin()->second;
	if((double)e.second/total > threshold) {
          ret.insert(m.first);
	}
	break;
      }
    }
  }

  ret.erase(host);
  return ret;
}

vector<pair<string, int>> conditional_multi(const streams_t & ss, const set<string> hosts, int window)
{
  vector<pair<string, int>> ret;
  return ret;
}


} //end namespace streams
} //end namespace dns
