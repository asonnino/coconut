function [ids, mu,sig] = analyse(json)
%ANALYSE Compute stiming mean and std.
%   Compute mean and standard deviation of timing for each machine.

% number of samples
m = size(json(:),1);

% get number of machines
requests = [json(:).request];
ids = unique([requests(:).machine_id]);
n = size(ids,2);
 
% number of samples per machine
m = size(json(:),1)/n;

% get ordered timings
timings = [json(:).time];
timings = reshape(timings,n,m);
timings = sort(timings,1);
timings = timings';

% subtract fixed delay
timings(:,2:end) = timings(:,2:end) - timings(:,1);

% compute delay for every possible threshold value
data = zeros(m,n);
for i=0:m-1
    for t=1:n
        data(i+1,t) = sum(timings(1+i:t+i));
    end
end


mu = mean(data);
sig = std(data);
    

% % sort data per machine ID -- each column of data contains 
% % timings for a specific machine ID
% data = zeros(m/n, n);
% for i = 1:n
%     tmp = json([requests(:).machine_id] == ids(i));
%     data(:,i) = [tmp(:).time];
% end
% 
% % compute mean and standard deviation
% mu = mean(data);
% sig = std(data);

end

