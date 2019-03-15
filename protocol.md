

###     1.任务订阅

矿机启动，首先以mining.subscribe方法向矿池连接，用来订阅工作。

矿池以mining.notify返回订阅号、ExtraNonce1和ExtraNonce2_size。

Client:

```
{
  "id": 1,
  "method": "mining.subscribe",
  "params": [
    "MinerName/1.0.0", 
	"TrueStratum/1.0.0",
	"session_id"
  ]
}
```

Server:

```
{
  "id": 1,
  "result": [
    [
      "mining.notify",
      "ae6812eb4cd7735a302a8a9dd95cf71f",
      "TrueStratum/1.0.0"
    ],
    "080c",
	4
  ],
  "error": null
}
```

其中：

订阅号:ae6812eb4cd7735a302a8a9dd95cf71f；

080c是extranonce，Extranonce可能最大3字节；

ExtraNonce2_size为4，矿机ExtraNonce2计数器的字节数。

session_id:订阅号ae6812eb4cd7735a302a8a9dd95cf71f,可选。


### 	2.矿机登录

矿机以mining.authorize方法，用某个帐号和密码登录到矿池，密码可空，矿池返回true登录成功。该方法必须是在初始化连接之后马上进行，否则矿机得不到矿池任务。

Client:

```
{"params":["miner1","password"],"id":2,"method":"mining.authorize"}
```

Server:

```
{"error":null,"id":2,"result":true}
```


### 	3.难度调整

难度调整由矿池下发给矿机，以mining.set_difficulty方法调整难度，params中是难度值。


Server:

```
{"id":null,"method":"mining.set_difficulty","params":["0545415ab8418cbb"]}
```

矿机会在下一个任务时采用新难度，矿池有时会马上下发一个新任务并且把清理任务设为true，以便矿机马上以新难度工作。
注：难度改为直接发送target,16字节长度。


### 	4.任务分配

该命令由矿池定期发给矿机，当矿机以mining.subscribe方法登记后，矿池应该马上以mining.notify返回该任务。


Server:

```
{
  "id": null,
  "method": "mining.notify",
  "params": [
    "bf0488aa",
    "abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c",
    "645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc",
    true
  ]
}
```

**任务ID**：bf0488aa；

**seedhash**：abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c。每一个任务都发送一个seedhash来支持尽可能多的矿池，这可能会很快地在货币之间交换。

**headerhash**: 645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc。

**boolean cleanjobs**:true。如果设为true，那么矿工需要清理任务队列，并立即开始从事新提供的任务，因为所有旧的任务分享都将导致陈旧的分享错误。如果是false则等当前任务结束才开始新任务。


### 	5.结果提交

矿工使用seedhash识别DataSet，然后带着headerhash,extranonce和自己的minernonce寻找低于目标的share(这是由提供的难度而产生的)。

矿机找到合法share时，就以”mining.submit“方法向矿池提交任务。矿池返回true即提交成功，如果失败则error中有具体原因。


Client:

```
{
  "id": 244,
  "method": "mining.submit",
  "params": [
    "username",
    "bf0488aa",
    "1060"
  ]
}
```

**任务ID**: bf0488aa

**minernonce**: 1060。minernonce为无符号64位的整数。


Server:

- 接受结果

```
{
  "id": 244,
  "result": true,
  "error": null
}
```

- 不被接受

```
{
    "id": 244,
    "result": false,
    "error": [

      -1,
      "Job not found",
      NULL
    ]
  }
```

### 	6.申请种子哈希

矿工使用seedhash识别DataSet，如果不匹配则向矿池申请种子哈希来生成DataSet。

矿池应该马上发送种子哈希给矿机(10240个)。


Client:

```
{
  "id": 5,
  "method": "mining.seedhash",
  "params": [
    "username",
    "bf0488aa"
  ]
}
```

**任务ID**: bf0488aa,用于标识请求对应的种子哈希


Server:

```
  "id": 5,
  "result": [
    [
      "323cf20198c2f3861e947d4f67e3ab63",
      "b7b2e24dcc9095bd9123e7b33371f6cc",
      "6510010198c2f3861e947d4f67e3ab63",
      "b7b2e24dcc9095bd9123e7b33371f6cc",
      ...
    ],
	"5684210198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b3337ab84c"
  ],
  "error": null
```

**result**: 10240个用于构建DataSet的种子哈希

**seedhash**: 用于验证构建后的DataSet



