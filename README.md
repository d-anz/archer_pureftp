<h2>简介</h2>
PUREFTP管理系统

<h2>特性</h2>
web管理
<h2>项目地址</h2>
GITHUB:<a href="https://github.com/SRELabs/pureftp">https://github.com/SRELabs/pureftp</a>
<h2>快速开始</h2>
<h3>安装</h3>
<pre class="lang:default decode:true ">cd /home/cloudsa/
mkdir pureftp.cloudsa.org
git clone git@github.com:SRELabs/pureftp.git pureftp.cloudsa.org</pre>
<h3>安装pip依赖</h3>
<pre class="lang:default decode:true">cd pureftp.cloudsa.org
pip install -r requirements.txt</pre>
<h3>修改配置文件</h3>
<pre class="lang:default decode:true">mv archer/settings.py.sample archer.setting.py</pre>
如果你使用sqlite3，数据库配置默认即可。如果想使用MySQL，那么请将配置文件中的mysql改为default即可。

vim archer/settings.py
<pre class="lang:default decode:true">DATABASES = {
    'mysql': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'archer_user',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': '3306',
    },
    'default':{
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'data/main.db'
    }
}</pre>

<h3>初始化数据</h3>
<pre class="lang:default decode:true">python manage.py migrate</pre>
<h3>创建管理员账户</h3>
<pre class="lang:default decode:true "># python manage.py createsuperuser
Username (leave blank to use 'root'): cloudsa
Email address: admin@cloudsa.org
Password:
Password (again):
Superuser created successfully.</pre>
<h3>启动</h3>
<pre class="lang:default decode:true ">python manage.py runserver</pre>
<h2>更新日志</h2>
2017-05-26

&nbsp;

&nbsp;
