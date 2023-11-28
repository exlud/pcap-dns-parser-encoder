#include <iostream>
#include "collector.h"

namespace dns {

collector::collector()
{

}

void collector::collect(const std::tuple<time_t, int, bool, std::string> query)
{
  _queries.push_back(query);
}

int collector::grouping(int margin)
{
  std::vector<std::tuple<time_t, int, bool, std::string>> group;
  time_t pts = 0;
  for(auto it = _queries.begin(); it != _queries.end(); it++) {
    time_t ts = std::get<0>(*it);
    if((ts - pts) > margin && !group.empty()) {
      _groups.push_back(group);
      group.clear();
    }

    group.push_back(*it);
    pts = ts;
  }

  if(!group.empty()) {
    _groups.push_back(group);
  }

  std::cout << _queries.size() << " queries split into " << _groups.size() << " groups" << std::endl;
  std::cout << "with time distance no less than " << (margin-1) << " seconds" << std::endl;
  return _groups.size();
}

int collector::causing(int pulse)
{
  std::tuple<std::string, std::vector<std::string>> causal;
  std::string cause;
  std::vector<std::string> effect;
  std::set<std::string> ueffect;

  for(auto it = _groups.begin(); it != _groups.end(); it++) {
    const auto group = *it;
    cause.clear();
    effect.clear();
    ueffect.clear();
    int id = -1;

    // find the first query
    for(auto qit = group.begin(); qit != group.end(); qit++) {
      const auto query = *qit;
      bool qr = std::get<2>(query);
      if(qr) {
        cause = std::get<3>(query);
        ueffect.insert(cause);
	id = std::get<1>(query);
	break;
      }
    }
    if(cause.empty() || id == -1) {
      break;
    }


    // find the response share the same id
    auto rit = group.begin();
    for(; rit != group.end(); rit++) {
      const auto resp = *rit;
      int rid = std::get<1>(resp);
      if(std::get<2>(resp) == false && rid == id) {
        break;
      }
    }
    if(rit == group.end()) {
      break;
    }

    // push all effects 'pulse' seconds afterwards
    time_t ts = std::get<0>(*rit);
    for(; rit != group.end(); rit++) {
      const auto query = *rit;
      if(std::get<2>(query)) {
	time_t cts = std::get<0>(*rit);
	if((cts - ts) > pulse) {
          break;	
	}
	auto name = std::get<3>(query);
	if(ueffect.find(name) == ueffect.end()) {
          effect.push_back(name);
	  ueffect.insert(name);
	}
      }
    }

    // if cause and effect are not empty, it is a candidate of causality
    if(!cause.empty() && !effect.empty()) {
      _causals.push_back(std::make_tuple(cause, effect));
    }
  }

  std::cout << "find " << _causals.size() << " candidates" << std::endl;
  std::cout << "with pulse effect no greater than " << (pulse+1) << " seconds" << std::endl;
  return _causals.size();
}

void collector::report()
{
  for(auto it = _causals.begin(); it != _causals.end(); it++) {
    const auto candidate = *it;
    const auto cause = std::get<0>(candidate);
    const auto effect = std::get<1>(candidate);

    std::cout << std::endl;
    std::cout << "cause " << cause << std::endl;
    std::cout << "effect" << std::endl;
    for(auto eit = effect.begin(); eit != effect.end(); eit++) {
      std::cout << "    " << *eit << std::endl;
    }
  }

  return;
}

}
