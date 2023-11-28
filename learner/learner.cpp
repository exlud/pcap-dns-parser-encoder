#include <iostream>
#include <iomanip>
#include "learner.h"

namespace dns {

learner::learner()
{

}

void learner::feed(std::tuple<std::string, std::vector<std::string>> candidate)
{
  auto cause = std::get<0>(candidate);
  auto effect = std::get<1>(candidate);

  auto search = _causaldb.find(cause);
  if(search == _causaldb.end()) {
    std::map<std::string, int> dict;
    for(auto it = effect.begin(); it != effect.end(); it++) {
      dict.insert({*it, 1});
    }
    _causaldb.insert({cause, std::make_tuple(1, dict)});
    return;
  }

  auto val = search->second;
  auto hit = std::get<0>(val) + 1;
  auto dict = std::get<1>(val); 
  for(auto it = effect.begin(); it != effect.end(); it++) {
    auto dit = dict.find(*it);
    if(dit == dict.end()) {
      dict.insert({*it, 1});
    } else {
      dict[*it] = dit->second + 1;
    }
  }

  _causaldb[cause] = std::make_tuple(hit, dict);

  return;
}

void learner::summary()
{
  for(auto m : _causaldb) {
    auto val = m.second;
    auto hit = std::get<0>(val);
    std::cout << std::endl;
    std::cout << m.first << " hit " << hit << " times" << std::endl;
    std::cout << "conditional probability" << std::endl;

    auto dict = std::get<1>(val);
    for(auto n : dict) {
      std::cout << std::fixed;
      std::cout << std::setprecision(2);
      std::cout << "    " << n.first << "  " << (double)n.second/hit << std::endl;
    }
  }
  return;
}


}
