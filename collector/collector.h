#ifndef DNS_COLLECTOR_H
#define DNS_COLLECTOR_H

#include <vector>
#include <set>
#include <tuple>
#include <string>
#include <ctime>

namespace dns {

class collector {
  public:
    collector();
    void collect(const std::tuple<time_t, int, bool, std::string> query);
    int grouping(int margin = 5);
    int causing(int pulse = 2);
    void report();
    std::vector<std::tuple<std::string, std::vector<std::string>>> _causals;

  private:
    std::vector<std::tuple<time_t, int, bool, std::string>> _queries;
    std::vector<std::vector<std::tuple<time_t, int, bool, std::string>>> _groups;
};

}

#endif
