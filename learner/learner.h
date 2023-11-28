#ifndef DNS_LEARNER_H
#define DNS_LEARNER_H

#include <vector>
#include <set>
#include <map>
#include <tuple>
#include <string>

namespace dns {

class learner {
  public:
    learner();
    void feed(std::tuple<std::string, std::vector<std::string>> candidate);
    void summary();

  private:
    std::map<std::string, std::tuple<int, std::map<std::string, int>>> _causaldb;
};

}

#endif
