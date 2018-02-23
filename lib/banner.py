import random

VERSION = "1.4.0"


def banner_1(line_sep="#--", space=" " * 30):
    print("""\033[1m\033[36m{space_sep}_____     _       _____     _     _ _
{sep1}Author : Vector/NullArray |  _  |_ _| |_ ___|   __|___| |___|_| |_
{sep1}Twitter: @Real__Vector    |     | | |  _| . |__   | . | | . | |  _|
{sep1}Type   : Mass Exploiter   |__|__|___|_| |___|_____|  _|_|___|_|_|
{sep1}Version: {v_num}                                    |_|
##############################################\033[0m
    """.format(sep1=line_sep, v_num=VERSION, space_sep=space))


def banner_2():
    print(r"""
{blue}--+{end} {red}Graffiti the world with exploits{end} {blue}+--{end}
{blue}--+{end}             __   ____            {blue}+--{end} 
{blue}--+{end}            / _\ / ___)           {blue}+--{end}
{blue}--+{end}           /    \\___ \           {blue}+--{end}
{blue}--+{end}           \_/\_/(____/           {blue}+--{end}
{blue}--+{end}            {red}AutoSploit{end}            {blue}+--{end}
{blue}--+{end}           NullArray/Eku          {blue}+--{end}
{blue}--+{end}             v({red}{vnum}{end})             {blue}+--{end}
    """.format(vnum=VERSION, blue="\033[36m", red="\033[31m", end="\033[0m"))


def banner_3():
    print(r'''#SploitaSaurus Rex{green}
                                           O_
                                          /  >
                                        -  >  ^\
                                      /   >  ^ /   
                                    (O)  >  ^ /   / / /  
       _____                        |            \\|//
      /  __ \                      _/      /     / _/
     /  /  | |                    /       /     / /
   _/  |___/ /                   /      ------_/ / 
 ==_|  \____/                 _/       /  ______/
     \   \                 __/           |\
      |   \_          ____/              / \      _                    
       \    \________/                  |\  \----/_V
        \_                              / \_______ V
          \__                /       \ /          V
             \               \        \
              \______         \_       \
                     \__________\_      \ 
                        /    /    \_    | 
                       |   _/       \   |
                      /  _/          \  |
                     |  /            |  |
                     \  \__          |   \__
                     /\____=\       /\_____=\{end} v({vnum})'''''.format(
        green="\033[1m\033[32m", end="\033[0m", vnum=VERSION
    ))

    
def banner_4():
    print(r"""
{red}    .__.    ,     __.   .     , 	{end}
{red}    [__]. .-+- _ (__ ._ | _ *-+-	{end}
{red}    |  |(_| | (_).__)[_)|(_)| | 	{end}
{red}                 |          	{end}
{red}          _ ._  _ , _ ._		{end}
{red}         (_ ' ( `  )_  .__)	{end}
{red}       ( (  (    )   `)  ) _)	{end}
{red}      (__ (_   (_ . _) _) ,__)	{end}
{red}          `~~`\ ' . /`~~`		{end}
{red}               ;   ;		{end}
{red}               /   \		{end}
{red} _____________/_ __ \_____________ {end}

{blue}--------The Nuclear Option--------{end}
{blue}-----+v({red}{vnum}{end})   +-----{end}
{blue}-----------NullArray/Eku----------{end}	  
{blue}__________________________________{end}
	""".format(vnum=VERSION, blue="\033[36m", red="\033[31m", end="\033[0m"))

def banner_main():
    """
    grab a random banner each run
    """
    banners = [
        banner_4 banner_3, banner_2, banner_1
    ]
    return random.choice(banners)()
