---
title: "GoLang-Gin框架入门"
date: 2024-01-25 08:30:23 +0800
category: Program
tags: [Program,golang]
excerpt: GoLang-Gin框架入门
---
## 入门

```
func main() {
	r := gin.Default()
	r.GET("/hello", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"name": "zhangsan",
		})
	})
	err := r.Run(":8080")
	if err != nil {

	}
}
```

## 路由

- 路由uri到函数得映射

### RESTful API规范

### 请求方法

```
//get请求
r.GET("/hello", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"name": "zhangsan",
		})
	})
//post请求
r.POST("/save", func(ctx *gin.Context) {
		ctx.JSON(200, "post")
	})
	
//Any 接受所有请求
r.Any("/save", func(ctx *gin.Context) {
		ctx.JSON(200, "post")
	})
```

### URI

- 静态url

  比如 /he1lo ， /user/find

- 路径参数，

  比如 /user/find/:id

```
	//http://ip:8080/hello/aaa
	//获取路径的值
	r.GET("/hello/:id", func(ctx *gin.Context) {
		ctx.JSON(200, ctx.Param("id"))
	})
```

- 模糊匹配

  比如 /user/\*path ,   比如 /user/\*

```
//http://ip:8080/hello/aaa/aaaaaaaaaa
//会匹配出/aaa/aaaaaaaaaa
	r.GET("/hello/*path", func(ctx *gin.Context) {
		ctx.JSON(200, ctx.Param("path"))
	})
```



### 处理函数

- 通过上下文的参数，获取http的请求参数，响应http请求等

```
type HandlerFunc func(*Context)
```

### 分组路由

```
	//http://ip:8080/v1/save
	v1 := r.Group("/v1")
	{
		v1.Any("/save", func(ctx *gin.Context) {
			ctx.JSON(200, "v1 post")
		})
	}
	//http://ip:8080/v2/save
	v2 := r.Group("/v2")
	{
		v2.Any("/save", func(ctx *gin.Context) {
			ctx.JSON(200, "v2 post")
		})
	}
```

## 获取参数

### GET

http://ip:8080/hello?id=123&name=zhangsan&address2=tianjing&address=beijing

```
	r.GET("/hello", func(ctx *gin.Context) {
		//Query : 获取确认存在的参数
		id := ctx.Query("id")
		name := ctx.Query("name")
		//GetQuery : 不确认是否存在的参数, 如果存在 ok 返回ture
		address, ok := ctx.GetQuery("address")
		//DefaultQuery : 如果参数不存在,给它一个默认的值
		address2 := ctx.DefaultQuery("address2", "北京")
		ctx.JSON(200, gin.H{
			"id":       id,
			"name":     name,
			"address":  address,
			"ok":       ok,
			"address2": address2,
		})
	})
```

上面的GetQuery,DefaultQuery,Query返回string类型, 但是如上面的例子`id`是int, 所以返回的值也会变成string, 如果想返回原格式类型

解决方法

http://ip:8080/hello?id=123&name=zhangsan

```
type User struct {
	Id   int64  `form:"id"`
	Name string `form:"name"`
	//ShouldBindQuery() 必须的参数
	//如果使用ShouldBindQuery(),无Address参数会会报错
	Address string `form:"address binding:"required"`
}

//func main() {
	r := gin.Default()

	r.GET("/hello", func(ctx *gin.Context) {
		var user User
		err := ctx.BindQuery(&user)
		if err != nil {
		}

		ctx.JSON(200, user)
	})
```

#### 数组参数

多个相同参数名的参数: http://ip:8080/hello?name=123&name=zhangsan

```
	r.GET("/hello", func(ctx *gin.Context) {
	//QueryArray()  确定有的参数
	//如果不确定是否有参数,使用GetQueryArray()
		name := ctx.QueryArray("name")
		ctx.JSON(200, name)
	})
```

- 绑定的

```
type User struct {
	Id   int64  `form:"id"`
	Name string `form:"name"`
	//ShouldBindQuery() 必须的参数
	//如果使用ShouldBindQuery(),无Address参数会会报错
	Address []string `form:"address binding:"required"`
}

	r.GET("/hello", func(ctx *gin.Context) {
	    var user User
		ctx.ShouBindQuery(&user)
		ctx.JSON(200, user)
	})
```

#### map参数

http://ip:8080/hello?name[home]=Beijing&name[company]=shanghai

```
	r.GET("/hello", func(ctx *gin.Context) {
		name := ctx.QueryMap("name")
		ctx.JSON(200, name)
	})
	
	//返回
	{"company":"shanghai","home":"Beijing"}
```

### POST

#### 表单参数

```
POST /hello HTTP/1.1

id=123&name=zhangsan&address=shanghai&address=beijing&addressmap[map1]=map1&addressmap[map2]=map2
```

```
	r.POST("/hello", func(ctx *gin.Context) {
		id := ctx.PostForm("id")
		name := ctx.PostForm("name")
		address := ctx.PostFormArray("address")
		addressMap := ctx.PostFormMap("addressmap")
		ctx.JSON(200, gin.H{
			"id":         id,
			"name":       name,
			"address":    address,
			"addressmap": addressMap,
		})
	})
```

```
//返回
{"address":["shanghai","beijing"],"addressmap":{"map1":"map1","map2":"map2"},"id":"123","name":"zhangsan"}
```

- 也支持绑定

#### JSON

- ShouldBindJSON()

```
type User struct {
	Id         int64             `json:"id"`
	Name       string            `json:"name"`
	Address    []string          `json:"address" binding:"required"`
	AddressMap map[string]string `json:"addressMap"`
}

func main() {
	r := gin.Default()

	r.POST("/hello", func(ctx *gin.Context) {
		var user User
		ctx.ShouldBindJSON(&user)
		ctx.JSON(200, user)
	})
```

```
//request
POST /hello HTTP/1.1
Content-Type: application/json;charset=UTF-8

{"address":["shanghai","beijing"],"addressmap":{"map1":"map1","map2":"map2"},"id":123,"name":"zhangsan"}

//response
{"id":123,"name":"zhangsan","address":["shanghai","beijing"],"addressMap":{"map1":"map1","map2":"map2"}}
```

#### XML

- ShouldBindXML()

#### 路径参数

http://ip:8080/hello/aaa/bbb

```
	r.POST("/hello/:id/:name", func(ctx *gin.Context) {
		id := ctx.Param("id")
		name := ctx.Param("name")
		ctx.JSON(200, gin.H{
			"id":   id,
			"name": name,
		})
	})
```

- ShouldBindUri()

```
type User struct {
	Id         string             `json:"id" uri:"id"`
	Name       string            `json:"name" uri:"name"`
}

func main() {
	r := gin.Default()

	r.POST("/hello/:id/:name", func(ctx *gin.Context) {
		var user User
		ctx.ShouldBindUri(&user)
		ctx.JSON(200, user)
	})

```

```
//response
{"id":"aaa","name":"bbb"}
```

#### 文件参数(文件上传)

```
//request

POST /hello HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQit2QsPnj7R0enz7

------WebKitFormBoundaryQit2QsPnj7R0enz7
Content-Disposition: form-data; name="file"; filename="at.aspx"
Content-Type: image/jpeg

11111111111
------WebKitFormBoundaryQit2QsPnj7R0enz7--
```

- 一次上传多个文件

```
	r.POST("/hello", func(ctx *gin.Context) {
		form, err := ctx.MultipartForm()
		if err != nil {

		}
		value := form.Value
		files := form.File
		for _, fileArray := range files {
			for _, v := range fileArray {
				ctx.SaveUploadedFile(v, "/tmp/"+v.Filename)
			}
		}
		ctx.JSON(200, value)
	})
```

- 单个文件上传

```
	r.POST("/hello", func(ctx *gin.Context) {
		file, err := ctx.FormFile("file")
		if err != nil {
			ctx.String(http.StatusInternalServerError, "读取file失败: "+err.Error())
			return
		}
		ctx.SaveUploadedFile(file, "/tmp/"+file.Filename)
		ctx.String(http.StatusOK, "上传成功！")

		ctx.JSON(200, file.Filename)
	})
```

## 响应

### 字符串

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.String(200, "ok")
	})
```

### JSON

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"json": "json",
		})
```

### XML

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.XML(200, gin.H{
			"json": "json",
		})
```

### 文件格式(下载)

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.File("./1.png")
		//下载文件重名名
		ctx.FileAttachment("./1.png","保存的名字.png")
	})
```

### 设置相应头

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.Header("test","test" )
```

### 重定向

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.Redirect(301,"http://www.baidu.com" )
```

### YAML

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.YAML(200, gin.H{
			"json": "json",
		})
```

## 模板渲染

### 基本使用

- 占位符

```
//	/templates/index.tmpl
<!DOCTYPE html>
<html lang="en">
	<head>
	<meta charset="UTF-8"><title>Title</title>
</head>
<body>
	{{.title}}
</body>
</html>
```

```
	//读取模板文件
	r.LoadHTMLFiles("./templates/index.tmpl")
	r.Any("/hello", func(ctx *gin.Context) {
	//使用模板
		ctx.HTML(200, "index.tmpl", gin.H{
			"title": "hello template",
		})
	})
```

### 多个模板渲染

- LoadHTMLFiles

```
	//读取模板文件
	r.LoadHTMLFiles("./templates/index.tmpl","./templates/index1.tmpl","./templates/index2.tmpl")
	r.Any("/hello", func(ctx *gin.Context) {
	//使用模板
		ctx.HTML(200, "index.tmpl", gin.H{
			"title": "hello template",
		})
	})
```

- LoadHTMLGlob

```
	//解析templates目录下的所有模板文件
	r.LoadHTMLGlob("./templates/**")
	r.Any("/hello", func(ctx *gin.Context) {
	//使用模板
		ctx.HTML(200, "index.tmpl", gin.H{
			"title": "hello template",
		})
	})
```

```
// **/* 代表所有子目录下的所有文件
	r.LoadHTMLGlob("./templates/**/*")
	r.Any("/hello", func(ctx *gin.Context) {
	//使用模板
		ctx.HTML(200, "index.tmpl", gin.H{
			"title": "hello template",
		})
	})
```

### 自定义模板函数

```
	import "html/template"
	
	r.SetFuncMap(template.FuncMap{
		"safe": func(str string) template.HTML {
			return template.HTML(str)
		},
	})
```

### 静态文件处理

```
r.Static("/css", "服务器中静态文件所在的文件夹")
```

## 会话

### cookie

- 设置cookie

```
func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)
```

```
	r.Any("/hello", func(ctx *gin.Context) {
		ctx.SetCookie("user", "admin", 3600, "/", "129.150.46.86", false, false)
		ctx.String(200, "index.tmpl")
	})
```

- 读取cookie

```
	r.Any("/h", func(ctx *gin.Context) {
		user, _ := ctx.Cookie("user")
		ctx.String(200, user)
	})
```

- 删除cookie

> 将maxAge设置为`-1`,达到删除cookie的目的

```
func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)
```

### session

在Gin框架中，我们可以依赖[gin-contrib/sessions](https://github.com/gin-contrib/sessions)中间件处理session

## 中间件

- Use()
