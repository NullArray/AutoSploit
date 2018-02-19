# AutoSploit
AutoSploit尝试自动化利用远程主机,通过使用Shodan.io API自动收集目标。该程序允许用户输入他们的平台特定的搜索查询，如： Apache、IIS等等，候选者列表将被检索。

完成这个操作后，程序的“Exploit”组件就会通过运行一系列的Metasploit模块来尝试利用这些目标。通过以编程方式将模块的名称与初始搜索查询进行比较来确定将采用哪些Metasploit模块。然而，我已经增加了在“Hail Mary”类型的攻击中针对目标运行所有可用模块的功能。

已经选择了可用的Metasploit模块来促进远程代码执行并尝试获得反向TCP Shell和/或Meterpreter会话。通过“Exploit”组件启动之前出现的对话框配置工作区，本地主机和本地端口（用于MSF便利的后端连接）。

#### 操作安全考虑
从OPSEC的角度来看，在本地机器上接收连接可能不是最好的想法。 请考虑从具有所需的所有依赖性的VPS运行此工具。

# 用法
克隆 repo， 或者通过Docker进行部署。 详细信息可以在这里找到特别感谢Khast3x在这方面的贡献。

>git clone https://github.com/NullArray/AutoSploit.git

您可以从终端用python autosploit.py启动。 启动后，您可以选择五个操作之一。 请参阅下面的选项摘要。

```bash
+------------------+----------------------------------------------------+
|     Option       |                   Summary                          |
+------------------+----------------------------------------------------+
|1. Usage          | Display this informational message.                |
|2. Gather Hosts   | Query Shodan for a list of platform specific IPs.  |
|3. View Hosts     | Print gathered IPs/RHOSTS.                         |
|4. Exploit        | Configure MSF and Start exploiting gathered targets|
|5. Quit           | Exits AutoSploit.                                  |
+------------------+----------------------------------------------------+
```
# 可选模块

RCE选择了该工具提供的Metasploit模块。 您可以在本仓库的modules.txt文件中找到它们。 如果您希望添加更多或其他模块，请按以下格式进行。

>use exploit/linux/http/netgear_wnr2000_rce;exploit -j; 

每个新的模块都有自己的所属

# 依赖

AutoSploit依赖于以下Python2.7模块。

```bash
shodan
blessings
```

如果你发现你没有安装这些软件，就像这样用pip来获取它们。

```bash
pip install shodan
pip install blessings
```
由于程序调用了Metasploit框架的功能，所以你也需要安装它。 通过点击[这里](https://www.rapid7.com/products/metasploit/)从Rapid7获取它。

# 注意

虽然这不完全是一个Beta版本，但它是一个早期版本，因为这样的工具可能会在未来发生变化。如果您碰巧遇到了错误，或者希望为工具的改进做出贡献，请随时[打开工单](https://github.com/NullArray/AutoSploit/issues)或[提交合并请求](https://github.com/NullArray/AutoSploit/pulls)

感谢！

