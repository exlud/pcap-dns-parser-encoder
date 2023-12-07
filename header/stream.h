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
    set<string> window(milliseconds start, milliseconds end) const;
    vector<set<string>> adjacent(const string, int milli) const;
    vector<set<string>> adjacent_forward(const string, int milli);
    vector<set<string>> adjacent_backward(const string, int milli);

  private:
    vector<dns_event_t> stream_;
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
