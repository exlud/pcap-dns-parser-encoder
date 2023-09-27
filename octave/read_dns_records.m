function [timestamp, host, type] = read_dns_records(filename)
  system(["../scripts/extract-xy.sh " filename]);
  files = cellstr(strcat ([filename; filename], [".x"; ".y"]));
  tsfile = files{1};
  qfile = files{2};

  timestamp = dlmread(tsfile);
  % rebase the time, large numbers are incomprehensive to human
  origin = floor(timestamp(1));
  timestamp = timestamp-origin;
  qfid = fopen(qfile);
  buffer = textscan(qfid, "%s %s");
  host = buffer{1};
  type = buffer{2};
endfunction
