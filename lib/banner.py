import os
import random

VERSION = "2.2"
COLOR_CODEX = {
    "red": "\033[31m", "bright red": "\033[1m\033[31m",
    "blue": "\033[36m", "bright blue": "\033[1m\033[36m",
    "green": "\033[32m", "bright green": "\033[1m\033[32m",
    "grey": "\033[37m", "white": "\033[1m\033[38m",
    "end": "\033[0m"
}


def banner_1(line_sep="#--", space=" " * 30):
    banner = """\033[1m\033[36m{space_sep}_____     _       _____     _     _ _
{sep1}Author : Vector/NullArray |  _  |_ _| |_ ___|   __|___| |___|_| |_
{sep1}Twitter: @Real__Vector    |     | | |  _| . |__   | . | | . | |  _|
{sep1}Type   : Mass Exploiter   |__|__|___|_| |___|_____|  _|_|___|_|_|
{sep1}Version: {v_num}{spacer}                              |_|
##############################################\033[0m
    """.format(sep1=line_sep, v_num=VERSION, space_sep=space, spacer=" " * 8)
    return banner


def banner_2():
    banner = r"""
{blue}--+{end} {red}Graffiti the world with exploits{end} {blue}+--{end}
{blue}--+{end}             __   ____            {blue}+--{end} 
{blue}--+{end}            / _\ / ___)           {blue}+--{end}
{blue}--+{end}           /    \\___ \           {blue}+--{end}
{blue}--+{end}           \_/\_/(____/           {blue}+--{end}
{blue}--+{end}            {red}AutoSploit{end}            {blue}+--{end}
{blue}--+{end}           NullArray/Eku          {blue}+--{end}
{blue}--+{end}{minor_space2}             v({red}{vnum}{end}){minor_space}             {blue}+--{end}
    """.format(
        vnum=VERSION, blue=COLOR_CODEX["blue"], red=COLOR_CODEX["red"], end=COLOR_CODEX["end"],
        minor_space=" " * 1 if len(VERSION) == 3 else "",
        minor_space2=" " * 1 if len(VERSION) == 3 else ""
    )
    return banner


def banner_3():
    banner = r'''#SploitaSaurusRex{green}
                                           O_  RAWR!!
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
        green=COLOR_CODEX["bright green"], end=COLOR_CODEX["end"], vnum=VERSION
    )
    return banner

    
def banner_4():
    banner = r"""
{red}    .__.    ,     __.   .     , 	{end}
{red}    [__]. .-+- _ (__ ._ | _ *-+-	{end}
{red}    |  |(_| | (_).__)[_)|(_)| | 	{end}
{red}                     |          	{end}
{red}          _ ._  _ , _ ._		{end}
{red}         (_ ' ( `  )_  .__)	{end}
{red}       ( (  (    )   `)  ) _)	{end}
{red}      (__ (_   (_ . _) _) ,__)	{end}
{red}          `~~`\ ' . /`~~`		{end}
{red}               ;   ;		{end}
{red}               /   \		{end}
{red} _____________/_ __ \_____________ {end}

{blue}--------The Nuclear Option--------{end}
{blue}-----+       v({red}{vnum}{end}{blue}){spacer}+-----{end}
{blue}-----------NullArray/Eku----------{end}	  
{blue}__________________________________{end}
    """.format(
        vnum=VERSION, blue=COLOR_CODEX["blue"], red=COLOR_CODEX["red"], end=COLOR_CODEX["end"],
       spacer=" " * 9 if len(VERSION) == 3 else " " * 7
    )
    return banner


def banner_5():
    banner = r"""
                  {red}. '  .{end}
               {red}' .( '.) '{end}
       {white}_{end}     {red}('-.)' (`'.) '{end}
      {white}|0|{end}{red}- -(  #autosploit  ){end}
   {grey}.--{end}{white}`+'{end}{grey}--.{end}  {red}.  (' -,).(') .{end}
   {grey}|`-----'|{end}   {red}(' .) - ('. ){end}
   {grey}|       |{end}    {red}. (' `.  ){end}
   {grey}|  {red}.-.{end}  {grey}|{end}       {red}` .  `{end}
   {grey}| {red}(0.0){end}{grey} |{end}
   {grey}| {red}>|=|<{end} {grey}|{end}
   {grey}|  {red}`"`{end}{grey}  |{end}
   {grey}|       |{end}
   {grey}|       |{end}
   {grey}`-.___.-'{end}
   v({red}{version}{end})
    """.format(
        end=COLOR_CODEX["end"], grey=COLOR_CODEX["grey"], white=COLOR_CODEX["white"],
        version=VERSION, red=COLOR_CODEX["red"]
    )
    return banner


def banner_6():
    banner = r"""{red}
  ________              _____  _____.__  __  .__      
 /  _____/___________ _/ ____\/ ____\__|/  |_|__|     
/   \  __\_  __ \__  \\   __\\   __\|  \   __\  |     
\    \_\  \  | \// __ \|  |   |  |  |  ||  | |  |     
 \______  /__|  (____  /__|   |__|  |__||__| |__|     
        \/           \/{end}{green}                               
___________.__                                        
\__    ___/|  |__   ____                              
  |    |   |  |  \_/ __ \                             
  |    |   |   Y  \  ___/                             
  |____|   |___|  /\___  >                            
                \/     \/{blue}
 __      __            .__       .___                 
/  \    /  \___________|  |    __| _/                 
\   \/\/   /  _ \_  __ \  |   / __ |                  
 \        (  <_> )  | \/  |__/ /_/ |                  
  \__/\  / \____/|__|  |____/\____ |                  
       \/                         \/{end}{grey}     
 __      __.__  __  .__                               
/  \    /  \__|/  |_|  |__                            
\   \/\/   /  \   __\  |  \                           
 \        /|  ||  | |   Y  \                          
  \__/\  / |__||__| |___|  /                          
       \/                \/{end}{white}                           
___________              .__         .__  __          
\_   _____/__  _________ |  |   ____ |__|/  |_  ______
 |    __)_\  \/  /\____ \|  |  /  _ \|  \   __\/  ___/
 |        \>    < |  |_> >  |_(  <_> )  ||  |  \___ \ 
/_______  /__/\_ \|   __/|____/\____/|__||__| /____  >
        \/      \/|__|                             \/ {end}
{white}v{version}->NullArray/Eku{end}""".format(
        end=COLOR_CODEX["end"], grey=COLOR_CODEX["grey"], white=COLOR_CODEX["white"],
        version=VERSION, red=COLOR_CODEX["bright red"], green=COLOR_CODEX["bright green"],
        blue=COLOR_CODEX["bright blue"]
    )
    return banner


def banner_main():
    """
    grab a random banner each run
    """
    banners = [
        banner_6, banner_5, banner_4,
        banner_3, banner_2, banner_1
    ]
    if os.getenv("Graffiti", False):
        return banner_5()
    elif os.getenv("AutosploitOG", False):
        return banner_1()
    elif os.getenv("Nuclear", False):
        return banner_4()
    elif os.getenv("SploitaSaurusRex", False):
        return banner_3()
    elif os.getenv("Autosploit2", False):
        return banner_2()
    else:
        return random.choice(banners)()
