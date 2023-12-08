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
map<string, vector<pair<string, int>>> conditional(const streams_t & ss, int threshold = 10, int window = 1000);

// conditional probability statistic of multiple independent variable
// NOTE!
// relates to the volume and histro
// for example, if it needs 100 observations to pass the sample test in order to
//   depict the conditional distribution of one independent variable,
//   then to achieve the same level of confidence,
//   it needs 100^2 observations for 2 variables
//   100^3 observations for 3 variables
vector<pair<string, int>> conditional_multi(const streams_t & ss, const set<string> hosts, int window = 1000);

// helper function
// filter variables has significant high conditional probability
// either as dependent variable or independent variable
set<string> association(const map<string, vector<pair<string, int>>> & cdb, const string host, double threshold = 0.7);

const double alpha = 0.2;
// given an association set, the hypothesis is that:
//   it exist at least one sequence which
//   starts with one element as query,
//   followed by queries for others after it's response
//   in a short time window
//
// considering the noise in the given candidate association,
// hyperparameter 'noise'. the sequence can mismatch part of the set
//
// example:
//   association {A, B, C, D, E};
//   noise 1
//   window 1000ms  --> time window = 1000 + 0.2*1000*4 = 1800 ms
//
//   sequence:
//       AA'E        AA'BDCEE          CDEC'                BB'CDE             BCDEAB'       
//     --------------------------------------------------------------------------------------->t
//       1           2                 3                    4                  5
//   X denote the query for X, X' denote the response for X
//
//   sequence 1 & 2 & 4 follows the query-response definition
//   sequence 2 & 4 meets the `noise` requirement
//   sequence 2 is larger than sequence 4
//  
//  return:
//    sequence 2: ABDCE 
//
//  EXPLANATION of this hypothesis
//  the candidate association set is a statistic result
//  if it passes the hypothesis test, it maybe a necessary-causality tree
//  if it fails the test, it's definitely not a tree
//
//                        statistic            s                causality
//              ---------------------------    e
//              |     T      |     F      |    q
//              ---------------------------    u
//              |     A      |     C      | T  e      --->       T/F         
//              ---------------------------    n      
//              |     B      |     D      | F  c      --->        F
//              ---------------------------    e      
//  after statistic, get A&B
//  after hypothesis test, get A
//
//  if causality exists, sequence must exist --> if sequence does not exist, causality must not exist
//  then category B does the right rejection, but category A maybe not doing the right acceptance
vector<string> hypothesis(const streams_t & ss, const set<string> association, string & where, string & when, int noise, int window = 1000);

}//end namespace streams
}//end namespace dns

#endif
