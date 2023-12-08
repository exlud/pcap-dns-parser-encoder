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
using std::cout, std::endl;
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
      cout << "file: " << file << endl;
      cout << "error: " << msg << endl;
      continue;
    }
    streams.push_back(stream);
  }
  cout << "streams: " << streams.size() << endl;


  int volume = dns::streams::volume(streams);
  cout << "volume: " << volume << endl;

  auto space = dns::streams::space(streams);
  cout << "space: " << space.size() << endl;

  auto cdb = dns::streams::conditional(streams);
  string host = argv[1];
  double threshold = std::stod(argv[2]);
  auto association = dns::streams::association(cdb, host, threshold);
  if(association.empty()) {
    return 0;
  }
  cout << host << " associates to:" << endl; 
  for(auto a : association) {
    cout << "  " << a << endl;
  }
  association.insert(host);

  string where;
  string when;
  auto pattern = dns::streams::hypothesis(streams, association, where, when, 2, 1000);
  cout << "evidence found in " << where << " at " << when << endl;
  for(auto m : pattern) {
    cout << "  " << m << endl;
  }

  return 0;
}
