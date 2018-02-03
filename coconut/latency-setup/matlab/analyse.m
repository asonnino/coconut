function [ids, mu,sig] = analyse(json)
%ANALYSE Compute stiming mean and std.
%   Compute mean and standard deviation of timing for each machine.

% number of samples
%m = size(json(:),1);

% get number of machines
requests = [json(:).request];
%ids = unique([requests(:).machine_id]);
ids = 1:10;
n = size(ids,2);
 
% number of samples per machine
m = size(json(:),1)/n;

% get ordered timings
timings = [json(:).time];
timings = reshape(timings,n,m);
timings = sort(timings,1);
timings = timings';

% compute mean and std 
mu = mean(timings);
sig = std(timings);
    


end

