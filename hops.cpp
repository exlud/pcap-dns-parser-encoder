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

  int mili = std::stod(argv[4]);
  auto cdb = dns::streams::conditional(streams, 10, mili);
  auto est = dns::streams::estimate(cdb, space.size());

  string host = argv[1];
  double significance = std::stod(argv[2]);
  cout << host << endl;
  int hops = std::atoi(argv[3]);
  for(int i = 1; i <= hops; i++) {
    cout << "hops: " << i << endl;
    auto depen = dns::streams::recursive_search_significant_correlation(est, host, significance, i - 1);
    for(auto m : depen) {
      cout << m.first << " : " << m.second << endl;
    }
  }

  return 0;
}
