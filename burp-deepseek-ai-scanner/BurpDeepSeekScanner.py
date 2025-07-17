# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane, JTextField, JPanel, JLabel, BoxLayout, JScrollPane, JTextArea
from javax.swing import UIManager
from java.awt import Font, Dimension
from java.util import ArrayList
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import threading
import json
import traceback


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DeepSeek AI Vulnerability Scanner")

        # 默认漏洞列表
        self.vuln_types = [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Path Traversal",
            "Insecure Deserialization",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "Security Misconfiguration",
            "Using Components with Known Vulnerabilities",
            "Insufficient Logging & Monitoring"
        ]

        # 默认AI询问模板
        self.prompt_template = (
            "You are a professional web security analyst. "
            "Please analyze if the following HTTP request may have a potential %vuln_type% vulnerability. "
            "Provide your conclusion and reasoning clearly.\n\n%request%"
        )

        # 读取用户配置
        self.api_key, self.api_url, self.vuln_types, self.prompt_template = self.show_config_dialog()

        if not self.api_key or not self.api_url:
            self._callbacks.printError("API Key or API URL is empty, the extension may not work properly.")

        callbacks.registerContextMenuFactory(self)
        print("DeepSeek AI Vulnerability Scanner loaded")

    def show_config_dialog(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        # API Key
        panel.add(JLabel("DeepSeek API Key:"))
        api_key_field = JTextField(40)
        panel.add(api_key_field)

        # API URL
        panel.add(JLabel("DeepSeek API URL:"))
        api_url_field = JTextField(40)
        panel.add(api_url_field)

        # 漏洞类型
        panel.add(JLabel("Vulnerability Types (one per line):"))
        vuln_text_area = JTextArea("\n".join(self.vuln_types))
        vuln_text_area.setLineWrap(True)
        vuln_text_area.setWrapStyleWord(True)
        vuln_scroll = JScrollPane(vuln_text_area)
        vuln_scroll.setPreferredSize(Dimension(400, 150))
        panel.add(vuln_scroll)

        # AI提示模板
        panel.add(JLabel("AI Prompt Template (use %vuln_type% and %request% as placeholders):"))
        prompt_text_area = JTextArea(self.prompt_template)
        prompt_text_area.setLineWrap(True)
        prompt_text_area.setWrapStyleWord(True)
        prompt_scroll = JScrollPane(prompt_text_area)
        prompt_scroll.setPreferredSize(Dimension(400, 150))
        panel.add(prompt_scroll)

        result = JOptionPane.showConfirmDialog(None, panel, "DeepSeek Configuration", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            api_key = api_key_field.getText().strip()
            api_url = api_url_field.getText().strip()
            vuln_types = [line.strip() for line in vuln_text_area.getText().splitlines() if line.strip()]
            prompt_template = prompt_text_area.getText()
            return api_key, api_url, vuln_types, prompt_template
        else:
            return self.api_key, self.api_url, self.vuln_types, self.prompt_template

    def createMenuItems(self, invocation):
        menu = ArrayList()
        for vuln_type in self.vuln_types:
            item = JMenuItem(
                "Send to DeepSeek AI - " + vuln_type,
                actionPerformed=lambda event, v=vuln_type, inv=invocation: self.analyze_with_deepseek(v, inv)
            )
            menu.add(item)
        return menu

    def analyze_with_deepseek(self, vuln_type, invocation):
        try:
            if not self.api_key or not self.api_url:
                JOptionPane.showMessageDialog(None, "Please configure API Key and API URL first!", "Error", JOptionPane.ERROR_MESSAGE)
                return

            messages = invocation.getSelectedMessages()
            if not messages:
                self._callbacks.printError("No request selected.")
                return

            # ✅ 修复：发送完整 HTTP 请求（包含方法、头、Body）
            request = messages[0].getRequest()
            req_str = self._helpers.bytesToString(request)

            self._callbacks.printOutput("Sending request to DeepSeek, analysis type: %s" % vuln_type)
            threading.Thread(target=self.call_api, args=(req_str, vuln_type)).start()

        except Exception as e:
            self._callbacks.printError("Error in analyze_with_deepseek: %s" % str(e))
            self.show_result("Exception occurred in analyze_with_deepseek:\n" + traceback.format_exc())

    def call_api(self, code_text, vuln_type):
        try:
            url = URL(self.api_url)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Authorization", "Bearer " + self.api_key)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)

            # 用模板替换变量
            prompt_text = self.prompt_template.replace("%vuln_type%", vuln_type).replace("%request%", code_text)

            data = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a professional web security analyst. Please respond in concise Chinese."},
                    {"role": "user", "content": prompt_text}
                ]
            }
            json_data = json.dumps(data)

            out = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            out.write(json_data)
            out.flush()
            out.close()

            code = conn.getResponseCode()
            self._callbacks.printOutput("DeepSeek HTTP status code: %d" % code)

            if code == 200:
                reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
            else:
                reader = BufferedReader(InputStreamReader(conn.getErrorStream(), "UTF-8"))

            response = []
            line = reader.readLine()
            while line is not None:
                response.append(line)
                line = reader.readLine()
            reader.close()

            # ✅ 优化输出：自动换行，避免一行太长
            pretty_text = "\n".join(response)
            self.show_result(pretty_text)

        except Exception as e:
            err = "Exception calling DeepSeek API:\n%s" % traceback.format_exc()
            self._callbacks.printError(err)
            self.show_result(err)

    def show_result(self, text):
        UIManager.put("OptionPane.messageFont", Font("Microsoft YaHei", Font.PLAIN, 14))
        UIManager.put("OptionPane.buttonFont", Font("Microsoft YaHei", Font.PLAIN, 14))

        text_area = JTextArea(text)
        text_area.setLineWrap(True)
        text_area.setWrapStyleWord(True)
        text_area.setEditable(False)
        text_area.setFont(Font("Microsoft YaHei", Font.PLAIN, 14))
        scroll_pane = JScrollPane(text_area)
        scroll_pane.setPreferredSize(Dimension(600, 400))

        JOptionPane.showMessageDialog(None, scroll_pane, "DeepSeek Vulnerability Analysis Result", JOptionPane.INFORMATION_MESSAGE)
