## operational process

- 采用密码模式，直接从授权服务器获取JWT令牌
- 授权服务器与资源服务器拥有相同JWT签名
- 根据JWT令牌，通过资源服务器认证，获取资源

## 关于OAuth2的UserDetails

- 授权码模式

  面向微信用户，用户在微信上进行**确认**操作，相当于**验证UserDetails**

  授权服务器保存**用户**的账号密码、可访问的客户端id

- 密码模式

  面向本平台，客户端直接**传输**账号密码，相当于**验证UserDetails**

  授权服务器保存**客户端**的账号密码、可访问的客户端id

- **knowledge**

  资源服务器的资源需要相应权限才可访问，本项目统一给以上两种模式**都添加admin权限**

## 为什么在拥有令牌前先拥有授权码

- 用户登录后，授权服务器返回的数据是暴露在浏览器的，若直接返回令牌会把**令牌暴露**在浏览器

## bugs

- 资源服务器需要POST提交方式，写成了@GetMapping

  @RestqustMapping支持GET和POST提交方式

