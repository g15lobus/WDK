#!/usr/bin/python
# -*- coding: UTF-8 -*-
from gmpy2 import mpz,powmod,f_mod,mul

p=mpz(13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171)
g=mpz(26790476600736210439911326117339978371955050182095051707060863109260114006743503487596200818701323671541681934177621901008556022090467034705794892743945893)
h=mpz(4476678147226155115558365457750475595861521772603596936757528326067178243549776543712192144627870184928567432208656624794079113374237487568153440925199271)

y = pow(2,20)
print ("%d")%y

tab_x = {}
for i in range(y):
    result = f_mod(mul(powmod(g,(-i),p),h),p) #realizuje działanie h/g^i (mod p)
    tab_x[result] = i

for i in range(y):
    gx = powmod(powmod(g,y,p),i,p) #realizuje działanie (g^y)^i (mod p)
    if tab_x.has_key(gx): #przszukuje tablicę haszów w poszukiwaniu odpowiedniej wartości
        break
x = tab_x.get(gx)

x = i*y+x
print ("%s")%x