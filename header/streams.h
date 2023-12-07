#ifndef DNS_STREAMS_H
#define DNS_STREAMS_H
#include <vector>
#include <map>
#include <set>
#include <utility> //pair
#include <memory>
#include "stream.h"

using std::vector, std::map, std::set, std::pair;
using std::shared_ptr;

namespace dns {

typedef vector<shared_ptr<stream>> streams_t;

namespace streams {

// how many observations in all streams
int volume(const streams_t & ss);

// all variables occurred
set<string> space(const streams_t & ss);

// sorted <variable, occurrence>
vector<pair<string, int>> histro(const streams_t & ss, int threshold = 1);

// given condition 'host', what occurrs in a time window
// sorted pair
vector<pair<string, int>> conditional(const streams_t & ss, const string host, int window = 1000);

// list the conditonal samples of hosts, whose occurrence is larger than threshold
map<string, vector<pair<string, int>>> conditional(const streams_t & ss, int threshold = 5, int window = 1000);

// conditional probability statistic of multiple independent variable
// NOTE!
// relates to the volume and histro
// for example, if it needs 100 observations to pass the sample test in order to
//   depict the conditional distribution of one independent variable,
//   then to achieve the same level of confidence,
//   it needs 100^2 observations for 2 variables
//   100^3 observations for 3 variables
const double alpha = 0.85;
vector<pair<string, int>> conditional_multi(const streams_t & ss, const set<string> hosts, int window = 1000);

// helper function
// filter variables has significant high conditional probability
// either as dependent variable or independent variable
set<string> association(const map<string, vector<pair<string, int>>> & cdb, const string host, double threshold = 0.9);


}//end namespace streams
}//end namespace dns

#endif
