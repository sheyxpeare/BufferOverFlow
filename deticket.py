import urllib
import sys

################################################################################
#   Initiliaze Inputs
################################################################################
pads = ['01','02','03','04','05','06','07','08']
key = "0c80353a2c634be44096f9d7977bad4d60dcd000224743105c8eacc3f872e37a2e6c8afdaecba65e8d94754e15a587ea1620cf6b6bc59a0fe5d74400a7cabebbe9fa63236a1a6c90"

iv = key[0:16]
cipher = key[16:len(key)]


################################################################################
#   Define some high level functions in order to run the main code
################################################################################


#This function connects to oracle.php, inputs a ticket, and returns the output code (200 or 500)
def responsecode(ticket):
    url = "http://127.0.0.1/oracle.php?ticket="
    
    try:
        url = urllib.urlopen(url+ticket)
        res = url.read()
        rescode = url.getcode()

    except urllib.HTTPError as e:
        
        rescode = e.code
        res = e.read()

    if rescode == 200:
        return True
    else: return False

# This function was created as support for the hexcode generator function
# It breaks strings down into bytes (string size has to be two because 00-FF)

def break2(string):

    D = []
    
    for i in range(0,len(string)/2):
        br = []
        for j in range(0,2):
            br.append(string[2*i+j])
        d = ''.join(br)
        D.append(d)

    return D

# This function returns the hex value for a given byte from the last index to the front

def ivhex(st,idx,hx):

    D = break2(st)

    byte_idx = 7 - idx  # Backwards idx
    
    D[byte_idx] = hx


    return ''.join(D)

################################################################################
#   Decryption Functions
################################################################################

# This function changes the respective bytes of the initial vector so correct for padding
# for example, the second time around the last byte of the initial vector gets updated
# and the third time the last two bytes of the initial vector get updated, etc.

def updateiv(iv,idx,p):
    # First round we dont have to change the initial vector
    if idx == 0:
        return iv

    else:
        D = break2(iv)
        V = break2(p)


        byte_idx = 8 - idx
        count = 0

        # Changes the respective bytes of the initival vector into a new hex value
        # This is done so the initival vector has the correct padding when being decoded
        for j in range(byte_idx,8):
         
         
            t = str(hex(int(V[count],16) ^ int(pads[idx],16)))[2:]
            if len(t) == 1:
                t = '0' + t
            D[j] = t
            count = count + 1

        return ''.join(D)


# This function takes in two ciphertext blocks and decrypts them using oracle.php's response code

def decypher(iv,c):

    msg = ""
    dc = ""
    saved = 0
    p = ""

    ciphertext = c

    for i in range(0,8):

        
        ivinput = updateiv(iv,i,dc)
        
        # Looping thourgh 00-FF in order to find the correct padding
        for h in xrange(256):
        
            hx = str(hex(h)[2:].zfill(2))
            
            next = ivhex(ivinput,i,str(hx))
            
            #Check to see if padding is correct

            if responsecode(next+ciphertext):

                # For the correct padding, find the value of Dec(Ci) that created that padding
                f = str(hex(int(hx,16) ^ int(pads[i],16)))[2:]
                if len(f) == 1:
                    f = '0' + f
                dc = f + dc

                # Find the value of Pi (Pi = Dec(Ci) ^ Ci-1)
                t = (hex(int(break2(ivinput)[7-i],16) ^ int(f,16)))[2:]
                if len(t) == 1:
                   t = '0' + t
                      
                
                # Decode Pi from hex to string
                msg = t.decode("hex") + msg 
                p = p + t

                print "DECIPHERING:....:", msg 

                break

    return msg, dc
            

# This function takes the key and returns the decrypted message

def message(key,size):
    
    
    # Break the key down into 8 bytes (16 hex)
    cipherblocks = []
    for i in range(int(len(key)/(size*2))):
        c = []
        for j in range(size*2):
            c.append(key[i*size*2+j])
        d = ''.join(c)
        cipherblocks.append(d)

    message = ''
    dc = ''

    # Iterate through all blocks of the ciphertext and decode

    for i in range(len(cipherblocks)-1):
        m, d = decypher(cipherblocks[i],cipherblocks[i+1])
        message = message + m
        dc = dc + d
    print message

    return message, dc

################################################################################
#   RUN CODE TO DECRYPT
################################################################################


message(key,8)





   
