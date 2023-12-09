#include <iostream>
#include <string>
#include <utility>
#include <stdio.h>
#include <algorithm>
#include <filesystem>
#include "stream.h"
#include "streams.h"

using std::map, std::vector, std::set, std::pair;
using std::string;
using std::cout, std::endl, std::cerr;
using std::filesystem::directory_iterator;

int main(int argc, char * argv[])
{
  vector<string> files;
  string directory = "packet-samples/";
  for(auto file : directory_iterator(directory)) {
    if(file.path().extension() == ".pcap") {
      files.push_back(file.path().c_str());
    }
  }
  vector<std::shared_ptr<dns::stream>> streams;
  for(auto file : files) {
    auto stream = std::make_shared<dns::stream>(file);
    string msg;
    if(stream->load(msg) != 0) {
      cerr << "file: " << file << endl;
      cerr << "error: " << msg << endl;
      continue;
    }
    streams.push_back(stream);
  }
  cout << "streams: " << streams.size() << endl;

  int volume = dns::streams::volume(streams);
  cout << "volume: " << volume << endl;

  auto space = dns::streams::space(streams);
  cout << "space: " << space.size() << endl;
  cout << endl;

  auto cdb = dns::streams::conditional(streams);

  map<string, set<string>> cherry;
  auto histro = dns::streams::histro(streams, 10);
  for(auto h : histro) {
    string host = h.first;
    double threshold = 0.6;
    auto association = dns::streams::association(cdb, host, threshold);
    if(association.size() < 3) {
      continue;
    }
    association.insert(host);
    string where;
    string when;
    auto experimental_noise_level = []( int gsz){
      switch(gsz) {
        case 0:
	case 1:
	case 2:
	case 3:
	  return 0;
        case 4:
	case 5:
	  return 1;
	case 6:
	case 7:
	  return 2;
	case 8:
	case 9:
	case 10:
	  return 3;
	default:
	  return (gsz - 7);
      }
    };

    int noise = experimental_noise_level(association.size());
    auto pattern = dns::streams::hypothesis(streams, association, where, when, noise, 1000);
    if(pattern.empty()) {
      continue;
    }
    cout << "pattern found in " << where << " at " << when << endl;
    for(auto m : pattern) {
      cout << "  " << m << endl;
    }
    auto & v = cherry[where];
    v.insert(when);
    cout << endl;
  }

  for(auto m : cherry) {
    cout << "in file " << m.first << endl;
    cout << "timestamp:" << endl;
    for(auto e : m.second) {
      cout << "    " << e << endl;
    }
  }
  return 0;
}
