# -*- coding: utf-8 -*-
#!/usr/bin/python

def main():
    ciphertexts = ["56232e8cede71121d5b30365423401b094d57e59e982374d0f122ba50dc4587ec4436206874f21235a29667099d79e9e67052dfc8650fefdf865e867b99765ebc91bdb277b47663a5b4b",
"5c769e79e7ef0f6fd2b903404d82f9bf8ec069bd0edb82bd551835a511c2566c8b52295adfabd9774c31c09a7a10df9d7d1d3ffb875eeab0b750459bb58a65f4c9169a1e675267325b16f9ee849d9732467de2ae9c81c78288a4156fba61a9ed94c751630dba651088673697259336e9b0",
"56232e8cede71121d5b303405a280cb083d56ebc09db88b856168a071a8bf6b79d1132509300263e4d2d77797a10dfc978033ff42a94f0f3bd", 
"4b3f8e7dfce3078a3ef854104d2b1eb686c16412e29e98ef581423e91687137894139eb7931525775d3f6a729efb9e9961abc7fc87e302b0a85d4791b43db3ee82a87e5b29566b85bc45e1f08b9cde3a467af9bc9e2c2ad13e4fbe81fb6da0f39eda5787e1f5781e95762a9223853bbcee9da8436acddf00608d3dd3e61f411c2a2948881d3cb8b34a65b535aa73c5a045705375",
"4c338c61a6e91536cfac465e5c2216f185d6c2fbab9494a64c183da534c4456a87017715d81b83e45c312568351ac4806d033f526b07fdf1b55be97cb18961f78009db136606722f5a0af4f780949173156ae1a78ac96d4d34451379f5",
"5239cb64e3ef096fd3ba515146285bab868f7710ee8985bc55046fe61ac7136494172954d0052979",
"452c8e7dede14629c9b64853422815b095c6720af1db82a00f1626e914de13668d17285c77ea23364d20257b33ba272cb40437f28307e3fcb9125b3a5b8a72f68b15db077b4761391e1ff7e99789873907db22a5962c2ad13e4fbe81fb78e2d33539593103b82b0dda7b3b23ff8037fbf137130c76cbd60a799821dfa50d001c2127502fe668b4bd052df628e57a6b4d4f69423aad68567500333806a5e58c",
"4d399d6fe5fb4620d8a84c4741221fab8ecec2fba7db37734a5d38a505ca406a80083250931b2f775d3c77792904d0806d4f2dfe2dbea7fead565697f2de74e0850794576a49223057a113ed8098de3e136df1eb949cd89e3a47be9ffb72b74173cb513408bc600b8d796f83369721f7f797a8566fc3d013689e73daea141b18372454c4",
"5237cb74a6f80935d3aa56104526be53888f7d17ea98880baa1e2ea516c55564961f3a56d90e603845297f799ffcdfc97b069a0ec945fe545f125c8cbf8964e3801b3ff229566732fbe7521cc5979232467de2ae9c81c78288a4156fba61a9ed94c751630dba651088673697259336e9b0", 
"452c8e7defa81126d9bc59594d2b12fdc76abb1cab8cd2bf46b9caf114c2136f8b520b47d20829775e3a7f61301b7b556caae2f6c94cf2e2b1575edea4de70f68a168fb38c0666394e09f9f4848787301c705c4ed1c9f29f2c450073b222b2f13422552c11bb620f9b301a8a3f8833efe48ba8437bccd20a79969628fc5b41a9e43611881d8c54f2446250fba029c4aa51650a21088b176c49262747acf9d12240d0999ba808a80dfd25c48751b2afda785d9f64d94bcfcbd0556bd9d85e35c0e5fa81f7e952b7da3b2a7438b86a5dde60bda8c526e5d6b376d0cb", 
"452c8e7defa81c22d3b6575f5f2617b8c7d86e1ce790364a0f123fe00dca506120eb7515fd06257759216162331bd280244f34f68207f0e9bf5ee87bba9f20ed9b0d9504794970341e15f9fa9f87877d"]

    def wrapped(text):
        line_width = 40
        text_len = len(text)
        for chunk in xrange(0,text_len,line_width):
            if chunk > text_len-line_width:
                print str(chunk) + chr(9) + text[chunk:]
            else:
                print str(chunk) + chr(9) + text[chunk:chunk+line_width]
    
    def stringxor(s1,s2):
        return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
    
    s1 = ciphertexts[9].decode('hex')
    s2 = ciphertexts[10].decode('hex')
    
    s3 = stringxor(s1, s2)
    s3_len = len(s3)
    display_cribtext = "*" * s3_len
    
    print s3.encode('hex')
    answer = ''
    
    
    while (answer != 'end'):
        results = []
        crib = raw_input("Enter Crib:>")
        crib_len = len(crib)
        for i in range(len(s3)):
            text = s3[i:]
            print ("\n[%d]")%i
            message = stringxor(text,crib)
            results.append(message)
            print ("%s")%message
            
        answer = raw_input("Please enter the correct position of message, 'brak' if text isn't exists or 'end' to quit: ") 
        
        if(answer == 'end'):
            print "Your message is:" + display_cribtext
        elif (answer =='brak'):
            print("Without changes")
        else:
            answer = int(answer)
            print ("%s")%results[answer]
            display_cribtext = display_cribtext[:answer] + results[answer] + display_cribtext[answer+crib_len:]
            wrapped(display_cribtext)

main()