/* temporal adjacent illustration
event G happens at time t in a sequence:

       XA C       B  E   F     BGCD D C     X   X   X   AB
   ------------------------------------------------------->
                                                       time
apply time window:
                            [-w t +w]          

describe as: events {B, C, D} are temporally adjacent to event G
*/

#ifndef DNS_LEARNER_STREAM_H
#define DNS_LEARNER_STREAM_H

#include <map>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <ctime>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace dns {

using std::string;
using std::vector, std::map, std::set;
using std::chrono::seconds, std::chrono::microseconds, std::chrono::milliseconds;

typedef struct {
  milliseconds ts;
  string host;
} dns_query_event_t;

typedef struct {
  milliseconds ts;
  int tid;
  bool query;
  string host;
} dns_event_t;

class stream {
  public:
    explicit stream(const string file);
    stream() = delete;
    stream(const stream&) = delete;
    ~stream();

    string id();
    int load(string &);

    int volume();
    set<string> space();
    map<string, int> histro();
    bool contains(const set<string>);
    bool contains(const string);
    vector<string> sequence(const set<string> association, string & when, int noise, int window);
    set<string> window(milliseconds start, milliseconds end) const;
    vector<set<string>> adjacent(const string, int window) const;
    vector<set<string>> adjacent_forward(const string, int window);
    vector<set<string>> adjacent_backward(const string, int window);

  private:
    vector<dns_query_event_t> stream_;
    vector<dns_event_t> fullstream_;
    string file_;

  private:
    std::thread tload_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool loaded_;
    int errcode_;
    string errmsg_;
};


}

#endif
