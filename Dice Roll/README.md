# Details
**Author**: @JohnHammond#6971

**Description**: When you have just one source of randomness, it's "a die", but when you can have muliple -- it's 'dice!'

## Write Up:

Downloading the code, we can see that the program allows us to randomly generate a 32 bit integer that represents a dice roll, reset the random seed (“shake the dice”), or try to guess the outcome of the next dice roll.

Here is the original script:

``` py
#!/usr/bin/env python3

import random
import os

banner = """
              _______
   ______    | .   . |\\
  /     /\\   |   .   |.\\
 /  '  /  \\  | .   . |.'|
/_____/. . \\ |_______|.'|
\\ . . \\    /  \\ ' .   \\'|
 \\ . . \\  /    \\____'__\\|
  \\_____\\/

      D I C E   R O L L
"""

menu = """
0. Info
1. Shake the dice
2. Roll the dice (practice)
3. Guess the dice (test)
"""

dice_bits = 32
flag = open('flag.txt').read()

print(banner)

while 1:
        print(menu)

        try:
                entered = int(input('> '))
        except ValueError:
                print("ERROR: Please select a menu option")
                continue

        if entered not in [0, 1, 2, 3]:
                print("ERROR: Please select a menu option")
                continue

        if entered == 0:
                print("Our dice are loaded with a whopping 32 bits of randomness!")
                continue

        if entered == 1:
                print("Shaking all the dice...")
                random.seed(os.urandom(dice_bits))
                continue

        if entered == 2:
                print("Rolling the dice... the sum was:")
                print(random.getrandbits(dice_bits))
                continue

        if entered == 3:
                print("Guess the dice roll to win a flag! What will the sum total be?")
                try:
                        guess = int(input('> '))
                except ValueError:
                        print("ERROR: Please enter a valid number!")
                        continue

                total = random.getrandbits(dice_bits)
                if guess == total:
                        print("HOLY COW! YOU GUESSED IT RIGHT! Congratulations! Here is your flag:")
                        print(flag)
                else:
                        print("No, sorry, that was not correct... the sum total was:")
                        print(total)
```


Since seeding is optional and getrandbits (which is a deterministic, pseudo-random generator) is used, we should be able to predict values. I used tool randcrack to get 32-bit getrandbits integer inputs to predict newly generated numbers with high accuracy. And I wrote the following script to solve this challenge:

```py
import random, time
from randcrack import RandCrack
from pwn import *
import re

rc = RandCrack()

conn = remote('challenge.nahamcon.com', 31784)
conn.recv()

for i in range(624):
    print(i)
    conn.sendline(b"2")
    reci = conn.recv()
    rec_number = re.search("was:.* Info", str(reci))[0].replace("was:\\n", "").replace("\\n\\n0. Info","")
    rc.submit(int(rec_number))

print(rc.predict_randrange(0, 4294967295))
conn.interactive()
```

After the script has finished, we can see the flag.