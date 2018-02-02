function [json] = load_data(fname)
%LOAD_DATA load data int memory
%   FNAME: filename -- The file should contain a single json array.

% load the data into memory
fid = fopen(fname);
raw = fread(fid,inf);
str = char(raw');
json = jsondecode(str);

end

