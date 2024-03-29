#include <algorithm>
#include <iterator>
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
    std::move(one.begin(), one.end(), std::back_inserter(raw)); //merge results
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

void review(const streams_t & ss, const string host, const vector<string> association)
{
  for(auto s : ss) {
    s->review(host, association);
  }
}

vector<pair<string, int>> conditional(const streams_t & ss, const string host, const string extra, int window)
{
  vector<pair<string, int>> ret;

  // element of the vector means:
  // neighbors of the host, in one occurrence
  vector<set<string>> raw;

  for(auto s : ss) {
    auto one = s->adjacent(host, extra, window); //search in one stream
    std::move(one.begin(), one.end(), std::back_inserter(raw)); //merge results
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

map<string, vector<pair<string, double>>> estimate(const map<string, vector<pair<string, int>>> condition, int space)
{
  double a = 3 / space;

  map<string, vector<pair<string, double>>> ret;
  for(auto m : condition) {
    auto host = m.first;
    int total = m.second.begin()->second;
    vector<pair<string, double>> estimation;
    for(auto n : m.second) {
      estimation.push_back({n.first, (n.second + a)/(total + 3)}); 
    }

    ret[host] = estimation;
  }
  
  return ret;
}

static map<string, double> select_path(const vector<pair<string, double>> correlation)
{
  map<string, double> ret;
  for(auto m : correlation) {
    if(auto iter = ret.find(m.first);  iter != ret.end()) {
      if(iter->second >= m.second) {
        continue;
      }
    }
    ret[m.first] = m.second;
  }

  return ret;
}

map<string, double> search_significant_correlation(const map<string, vector<pair<string, double>>> estimation, const string var, double threshold)
{
  vector<pair<string, double>> correlation;
  for(auto e : estimation) {
    if(e.first == var) {
      for(auto c : e.second) {
        if(c.first != var && c.second > threshold) {
	  correlation.push_back({c.first, c.second});
	}
      }
      continue;
    }
    auto condition = e.first;
    for(auto c : e.second) {
      if(c.first == var && c.second > threshold) {
        correlation.push_back({condition, c.second});
	break;
      }
    }
  }


  return select_path(correlation);
}

map<string, double> recursive_search_significant_correlation(const map<string, vector<pair<string, double>>> estimation, const string var, double threshold, int depth)
{
  map<string, double> ret;
  ret = search_significant_correlation(estimation, var, threshold);
  for(int i = 0; i< depth; i++) {
    map<string, double> patches;
    for(auto m : ret) {
      if(m.second < threshold) {
        continue;
      }
      auto patch = search_significant_correlation(estimation, m.first, threshold/m.second);
      //auto patch = search_significant_correlation(estimation, m.first, threshold);
      for(auto & p : patch) {
        p.second *= m.second;
      }
      patches.merge(patch);
    }

    ret.merge(patches);
    vector<pair<string, double>> temp;
    std::transform(ret.begin(), ret.end(), std::back_inserter(temp), [](auto e){return e;});
    ret = select_path(temp);
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

vector<string> hypothesis(const streams_t & ss, const set<string> association, string & where, string & when, int noise, int window)
{
  vector<string> longest;
  for(auto s : ss) {
    string fwhen;
    auto ret = s->sequence(association, fwhen, noise, window);
    if(ret.size() > longest.size()) {
      longest = ret;
      where = s->id();
      when = fwhen;
    }
  }
  return longest;
}



} //end namespace streams
} //end namespace dns
