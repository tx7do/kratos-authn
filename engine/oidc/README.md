# OpenID Connect (OIDC)


## 什么是 OIDC

OIDC是一个OAuth2上层的简单身份层协议。它允许客户端验证用户的身份并获取基本的用户配置信息。OIDC使用JSON Web Token（JWT）作为信息返回，通过符合OAuth2的流程来获取。

OAuth2与资源访问和共享有关，而OIDC与用户身份验证有关。

其目的是为您提供多个站点的登录名。每次需要使用OIDC登录网站时，都会被重定向到登录的OpenID网站，然后再回到该网站。例如，如果选择使用Google帐户登录Auth0，这就使用了OIDC。成功通过Google身份验证并授权Auth0访问您的信息后，Google会将有关用户和执行的身份验证的信息发送回Auth0。此信息在JWT中返回，包含ID Token或者Access Token。

JWT包含Claims，它们是有关实体（通常是用户）的Claims（例如名称或电子邮件地址）和其他元数据。OIDC规范定义了一组标准的权利要求。这组标准声明包括姓名，电子邮件，性别，出生日期等。但是，如果要获取有关用户的信息，并且当前没有最能反映此信息的标准声明，则可以创建自定义声明并将其添加到令牌中。

较OAuth2，OIDC有一些不同的概念：

- OpenID Provider（OP），实现OIDC的OAuth2授权服务器
- Relying Party（RP），使用OIDC的OAuth2客户端
- End-User（EU），用户
- ID Token，JWT格式的授权Claims
- UserInfo Endpoint，用户信息接口，通过ID Token访问时返回用户信息，此端点必须为HTTPS

## OpenID Connect Discovery

