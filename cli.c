#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h> //getopt_long
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include "parser.h"

static void print_usages(const char * cmd)
{
  fprintf(stdout,
    "Extract DNS queries from a pcap file to encoded text\n"
    "Format:\n"
    "       1695634289.281076\n"
    "       prebid.media.net;6;I;\n"
    "       \n"
    "       1695634289.283082\n"
    "       aax.amazon-adsystem.com;4;I;\n"
    "       \n"
    "Explanation:        \n"
    "       1695634289.281076         timestamp\n"
    "       ;\n"
    "       aax.amazon-adsystem.com   host name\n"
    "       ;\n"
    "       4                         A record type\n"
    "       6                         AAAA record type\n"
    "       ?                         other record type\n"
    "       ;\n"
    "       I                         IN class\n"
    "       ?                         other class\n"
    "       ;\n"
    "       \n"
    "Usages: %s -f file.pcap -o out.file\n"
    "       %s -f file.pcap\n"
    "       %s -f file.pcap > out.file\n"
    "       find . -name *.pcap -exec %s -f {} \\;\n",
    cmd, cmd, cmd, cmd);
  return;
}

static struct option opts[] = {
  {"output", required_argument, 0, 'o'},
  {"file", required_argument, 0, 'f'},
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0},
};

int main(int argc, char **argv) {
  // shortcut for --help
  if(argc == 1) {
    print_usages(argv[0]);
    return 0;
  }

  char opt_f[256] = "", opt_o[256] = "";
  int opt;
  opterr = 0; //disable libc error message, handle error manually
  while((opt = getopt_long(argc, argv, "hf:o:", opts, NULL)) != -1) {
    switch (opt) {
    case 'h':
      print_usages(argv[0]);
      return 0;
    case 'f':
      strncpy(opt_f, optarg, strlen(optarg));
      break;
    case 'o':
      strncpy(opt_o, optarg, strlen(optarg));
      break;
    case '?':
      fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
      return -EINVAL;
    default:
      break;
    }
  }

  // source file validation
  if(strlen(opt_f) == 0) {
    fprintf(stderr, "Invalid option, must specify input file\n\n");
    print_usages(argv[0]);
    return -EINVAL;
  }
  if(access(opt_f, R_OK) != 0) {
    fprintf(stderr, "%s not readable or not exists\n", opt_f);
    return -EACCES;    
  }

  if(strlen(opt_o) == 0) {
    return parser(opt_f, NULL);
  } else {
    return parser(opt_f, opt_o);
  }
}
