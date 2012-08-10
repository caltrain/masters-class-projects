n=(1:1:50);
f1=((15*n-1)./(15*n+18*n.*n+3));
f2=((150*n-1)./(1770*n+1800*n.*n+30));
f3=((1500*n-1)./(179700*n+180000*n.*n+300));
plot(n,f1,n,f2,n,f3);
legend('m=3n','m=30n','m=300n');
title('Ratio of the flops in smart way by dumb way with repect to function of n');
xlabel('n');
ylabel('Ratio of flops for smart way by that of the dumb way');
