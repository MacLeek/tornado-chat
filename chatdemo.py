#!/usr/bin/env python
#coding: utf8
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.web
import os.path
import re
import time
import torndb
import uuid
import tornado.autoreload


from tornado import gen
from tornado.options import define, options, parse_command_line

define("port", default=8888, help="run on the given port", type=int)

''' 设置数据库'''
define("mysql_host", default="127.0.0.1:3306", help="database host")
define("mysql_database", default="chat", help="database name")
define("mysql_user", default="NAME", help="database user")
define("mysql_password", default="PASSWORD", help="database password")

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/user/(.*)", PrivateChatHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/a/message/new", MessageNewHandler),
            (r"/a/message/updates", MessageUpdatesHandler),
        ]
        settings = dict(
             cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
        )

        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)

        tornado.web.Application.__init__(self, handlers, **settings)

class MessageBuffer(tornado.web.RequestHandler):
    def __init__(self):
        self.waiters = set()
        self.cache = []
        self.cache_size = 200

    def wait_for_messages(self, callback, cursor=None):
        if cursor:
            new_count = 0
            for msg in reversed(self.cache):
                if msg["mid"] == cursor:
                    break
                new_count += 1
            if new_count:
                callback(self.cache[-new_count:])
                return
        self.waiters.add(callback)

    def cancel_wait(self, callback):
        self.waiters.remove(callback)

    def new_messages(self, messages):
        logging.info("Sending new message to %r listeners", len(self.waiters))
        for callback in self.waiters:
            try:
                callback(messages)
            except:
                logging.error("Error in waiter callback", exc_info=True)
        self.waiters = set()
        self.cache.extend(messages)
        if len(self.cache) > self.cache_size:
            self.cache = self.cache[-self.cache_size:]


# Making this a non-singleton is left as an exercise for the reader.
global_message_buffer = MessageBuffer()

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        nickname = self.get_secure_cookie("nickname")
        if not nickname: return None
        return nickname
    @property
    def db(self):
        return self.application.db
    def AddNewMessage(self,message):
        '''将新消息插入数据库'''
        try:
            self.db.execute(
                "insert into `messages` (`from`, `to`, `body`,`html`,`mid`) values (%s,%s,%s,%s,%s)",
                message["from"],message["to"],message["body"],message["html"],message["mid"]
                )           
        except:
            pass

class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        ownname = self.get_secure_cookie("nickname")
        '''仅显示对所有人发送的消息及在线用户'''
        msgs = [msg for msg in global_message_buffer.cache if msg["to"] == "All"]
        usrs = self.db.query("select username from users where username <> %s and online = %s",ownname,1)
        self.render("index.html", messages=msgs, users=usrs)

class PrivateChatHandler(BaseHandler):
    '''处理私人消息'''
    @tornado.web.authenticated
    def get(self,to_user):
        current_user = self.get_secure_cookie("nickname")
        if self.get_argument("to", None) != "All":
            msgs = [msg for msg in global_message_buffer.cache if msg["to"] == current_user and msg["from"] == to_user]
            self.render("private.html", messages=msgs,user=to_user)
        else:
            self.render("private.html",messages=[],user=to_user)

class MessageNewHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        message = {
            "mid": str(uuid.uuid4()),
            "time": time.strftime('%H:%M:%S',time.localtime(time.time())),
            "from": self.get_current_user(),
            "body": self.get_argument("body"),
            "to": self.get_argument("to","All")
        }
        print message
        message["html"] = tornado.escape.to_basestring(
            self.render_string("message.html", message=message))
        self.AddNewMessage(message)
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)
        global_message_buffer.new_messages([message])


class MessageUpdatesHandler(BaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        cursor = self.get_argument("cursor", None)
        global_message_buffer.wait_for_messages(self.on_new_messages,
                                                cursor=cursor)

    def on_new_messages(self, messages):
        # Closed client connection
        if self.request.connection.stream.closed():
            return
        self.finish(dict(messages=messages))

    def on_connection_close(self):
        global_message_buffer.cancel_wait(self.on_new_messages)

class AuthLoginHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        nickname = self.get_argument("nickname",None)
        ip = self.request.remote_ip 
        if nickname is None:
            '''昵称不能为空'''
            msg= 'Please input your nickname!'
            self.render("login.html",error=msg)
            return
        m = re.search(u'^[\u4e00-\u9fa50-9a-zA-Z_]+$', nickname)
        if m is None:
            '''昵称不能含有非法字符'''
            msg= 'Invalid character deteced,please use only with Chinese and letters!'
            self.render("login.html",error=msg)
            return
        user = self.db.get("select ip from users where username = %s",nickname)
        if user is not None:
            '''昵称不能重复'''
            msg='Nick name was already in use!'#System All
            self.render("login.html",error=msg)
        else:
            self.set_secure_cookie("nickname",nickname)
            try:
                '''插入用户信息'''
                self.db.execute("insert into `users` (`username`, `ip`, `online`) values (%s,%s,%s)",nickname,ip,1)
            except:
                self.redirect("/auth/login")
            message = {
                "mid": "special",
                "from": "System",
                "time": time.strftime('%H:%M:%S',time.localtime(time.time())),
                "to":"All",
                "body": "Welcome new user:"+nickname+" adding in!",
            }
            message["html"] = tornado.escape.to_basestring(    
            self.render_string("message.html", message=message))
            self.AddNewMessage(message)        
            if self.get_argument("next", None):
                self.redirect(self.get_argument("next"))
            else:
                self.write(message)
            global_message_buffer.new_messages([message])

    def get(self):
        msg=''
        self.render("login.html",error=msg)

class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("nickname")
        self.write("You are now logged out")
        self.deleted_online_user()
        self.redirect("/")
    def deleted_online_user(self):
        '''系统用户注销后在聊天室显示注销消息'''
        nickname = self.get_current_user()
        message = {
            "mid": "closed",
            "time": time.strftime('%H:%M:%S',time.localtime(time.time())),
            "from": "System",
            "body": nickname+" have disconnected from the web!",
            "to": self.get_argument("to","All")
        }
        try:
            self.db.execute(
                "update `users` set online = 0 where username = %s",nickname)
        except:
            pass
        message["html"] = tornado.escape.to_basestring(
            self.render_string("message.html", message=message))
        self.AddNewMessage(message)
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)
        global_message_buffer.new_messages([message])

def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
