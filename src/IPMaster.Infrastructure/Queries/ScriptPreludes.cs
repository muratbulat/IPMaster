namespace IPMaster.Infrastructure.Queries;

/// <summary>
/// Generated code placed before user scripts. It implements the manual's scripting API on top of the line bridge
/// (<see cref="ScriptBridge"/>): Input.Current, Input.Column, Output.Write, Remote.*; WSH additionally gets
/// Internal.CreateObject("Process"|"DNS"|"SNMP") (VBS-02). Python does not get the Internal objects (manual).
/// </summary>
internal static class ScriptPreludes
{
    public static readonly string[] RemoteFamilies =
        ["Files", "Groups", "JSON", "Nmap", "Performance", "PowerShell", "Registry", "SNMP", "SSH", "Services", "WMI", "XML"];

    public static string VbScript(string currentHex)
    {
        var remote = string.Concat(RemoteFamilies.Select(f =>
            $"  Public Function {f}(n)\r\n    {f} = IPM_Call(\"remote\", \"{f}\", CStr(n))\r\n  End Function\r\n"));
        return $$"""
            ' ---- IPMaster scripting API (generated) ----
            Function IPM_Hex(s)
              Dim i, r
              r = ""
              For i = 1 To Len(s)
                r = r & Right("000" & Hex(AscW(Mid(s, i, 1)) And &HFFFF&), 4)
              Next
              IPM_Hex = r
            End Function
            Function IPM_Unhex(h)
              Dim i, r
              r = ""
              For i = 1 To Len(h) Step 4
                r = r & ChrW(CLng("&H" & Mid(h, i, 4)))
              Next
              IPM_Unhex = r
            End Function
            Function IPM_Call(op, a, b)
              Dim line
              WScript.StdOut.WriteLine "@@IPM@@ " & op & " " & IPM_Hex(a) & " " & IPM_Hex(b)
              line = WScript.StdIn.ReadLine
              If Left(line, 3) = "ok " Then
                IPM_Call = IPM_Unhex(Mid(line, 4))
              Else
                Err.Raise vbObjectError + 513, "IPMaster", IPM_Unhex(Mid(line, 5))
              End If
            End Function
            Class IPM_InputClass
              Public Current
              Public Function Column(name)
                Column = IPM_Call("column", CStr(name), "")
              End Function
            End Class
            Class IPM_OutputClass
              Public Sub Write(text)
                WScript.StdOut.WriteLine "@@IPM@@ out " & IPM_Hex(CStr(text))
              End Sub
            End Class
            Class IPM_RemoteClass
            {{remote}}End Class
            Class IPM_List
              Private m_items()
              Private m_count
              Private Sub Class_Initialize()
                m_count = 0
                ReDim m_items(0)
              End Sub
              Public Sub Add(v)
                ReDim Preserve m_items(m_count)
                If IsObject(v) Then
                  Set m_items(m_count) = v
                Else
                  m_items(m_count) = v
                End If
                m_count = m_count + 1
              End Sub
              Public Property Get Count
                Count = m_count
              End Property
              Public Default Function Item(i)
                If IsObject(m_items(i)) Then
                  Set Item = m_items(i)
                Else
                  Item = m_items(i)
                End If
              End Function
            End Class
            Class IPM_Process
              Public ExitCode
              Public Output
              Private Sub Class_Initialize()
                ExitCode = 0
                Set Output = New IPM_List
              End Sub
              Public Sub Execute(commandLine)
                Dim sh, ex
                Set Output = New IPM_List
                Set sh = CreateObject("WScript.Shell")
                Set ex = sh.Exec(commandLine)
                Do While Not ex.StdOut.AtEndOfStream
                  Output.Add ex.StdOut.ReadLine
                Loop
                Do While ex.Status = 0
                  WScript.Sleep 20
                Loop
                ExitCode = ex.ExitCode
              End Sub
            End Class
            Class IPM_Dns
              Public Server
              Private Sub Class_Initialize()
                Server = ""
              End Sub
              Public Function GetName(target, recordType)
                GetName = IPM_Call("dns", CStr(target), CStr(recordType) & "|" & CStr(Server))
              End Function
            End Class
            Class IPM_SnmpQuery
              Public Version, PduType, Community, V3Security, V3AuthMode, V3PrivMode, V3UserName, V3AuthPass, V3PrivPass, MaxRepetitions, NonRepeaters
              Private m_oids
              Private Sub Class_Initialize()
                Version = 2
                PduType = &HA0
                Community = "public"
                V3Security = "NoAuthNoPriv"
                V3AuthMode = "SHA1"
                V3PrivMode = "AES"
                V3UserName = ""
                V3AuthPass = ""
                V3PrivPass = ""
                MaxRepetitions = 10
                NonRepeaters = 0
                m_oids = ""
              End Sub
              Public Sub AddOid(o)
                If m_oids = "" Then
                  m_oids = CStr(o)
                Else
                  m_oids = m_oids & "," & CStr(o)
                End If
              End Sub
              Public Sub SetOid(o)
                m_oids = CStr(o)
              End Sub
              Public Property Get OidList
                OidList = m_oids
              End Property
            End Class
            Class IPM_SnmpItem
              Public Oid, Value, [Type]
            End Class
            Class IPM_SnmpReply
              Public ErrorStatus, Items
              Private Sub Class_Initialize()
                ErrorStatus = 0
                Set Items = New IPM_List
              End Sub
            End Class
            Class IPM_Snmp
              Public Host, Query, Reply
              Private Sub Class_Initialize()
                Host = ""
                Set Query = New IPM_SnmpQuery
                Set Reply = New IPM_SnmpReply
              End Sub
              Public Function SendRequest()
                Dim p, r, lines, i, f, it
                p = "host=" & Host & vbLf & "version=" & Query.Version & vbLf & "pdutype=" & Query.PduType & vbLf & _
                    "community=" & Query.Community & vbLf & "v3security=" & Query.V3Security & vbLf & "v3authmode=" & Query.V3AuthMode & vbLf & _
                    "v3privmode=" & Query.V3PrivMode & vbLf & "v3username=" & Query.V3UserName & vbLf & "v3authpass=" & Query.V3AuthPass & vbLf & _
                    "v3privpass=" & Query.V3PrivPass & vbLf & "maxrepetitions=" & Query.MaxRepetitions & vbLf & "nonrepeaters=" & Query.NonRepeaters & vbLf & _
                    "oids=" & Query.OidList
                r = IPM_Call("snmp", p, "")
                lines = Split(r, vbLf)
                Set Reply = New IPM_SnmpReply
                Reply.ErrorStatus = CLng(lines(0))
                For i = 1 To UBound(lines)
                  f = Split(lines(i), vbTab, 3)
                  If UBound(f) = 2 Then
                    Set it = New IPM_SnmpItem
                    it.Oid = f(0)
                    it.[Type] = CLng(f(1))
                    it.Value = f(2)
                    Reply.Items.Add it
                  End If
                Next
                SendRequest = (Reply.ErrorStatus = 0)
              End Function
            End Class
            Class IPM_InternalClass
              Public Function CreateObject(kind)
                Select Case LCase(kind)
                  Case "process"
                    Set CreateObject = New IPM_Process
                  Case "dns"
                    Set CreateObject = New IPM_Dns
                  Case "snmp"
                    Set CreateObject = New IPM_Snmp
                  Case Else
                    Err.Raise 5, "Internal.CreateObject", "Unknown object '" & kind & "'. Use Process, DNS or SNMP."
                End Select
              End Function
            End Class
            Dim Input, Output, Remote, Internal
            Set Input = New IPM_InputClass
            Input.Current = IPM_Unhex("{{currentHex}}")
            Set Output = New IPM_OutputClass
            Set Remote = New IPM_RemoteClass
            Set Internal = New IPM_InternalClass
            ' ---- user script ----

            """;
    }

    public static string JScript(string currentHex)
    {
        var families = string.Join(",", RemoteFamilies.Select(f => $"\"{f}\""));
        return $$"""
            // ---- IPMaster scripting API (generated) ----
            function IPM_hex(s) { s = String(s); var r = ""; for (var i = 0; i < s.length; i++) { r += ("000" + s.charCodeAt(i).toString(16).toUpperCase()).slice(-4); } return r; }
            function IPM_unhex(h) { var r = ""; for (var i = 0; i < h.length; i += 4) { r += String.fromCharCode(parseInt(h.substr(i, 4), 16)); } return r; }
            function IPM_call(op, a, b) {
              WScript.StdOut.WriteLine("@@IPM@@ " + op + " " + IPM_hex(a) + " " + IPM_hex(b));
              var line = WScript.StdIn.ReadLine();
              if (line.substr(0, 3) == "ok ") return IPM_unhex(line.substr(3));
              throw new Error(IPM_unhex(line.substr(4)));
            }
            var Input = { Current: IPM_unhex("{{currentHex}}"), Column: function (n) { return IPM_call("column", n, ""); } };
            var Output = { Write: function (t) { WScript.StdOut.WriteLine("@@IPM@@ out " + IPM_hex(t)); } };
            var Remote = {};
            (function () { var f = [{{families}}]; for (var i = 0; i < f.length; i++) { (function (n) { Remote[n] = function (x) { return IPM_call("remote", n, x); }; })(f[i]); } })();
            function IPM_Process() { this.ExitCode = 0; this.Output = []; this.Output.Count = 0; }
            IPM_Process.prototype.Execute = function (cmd) {
              var ex = new ActiveXObject("WScript.Shell").Exec(cmd), out = [];
              while (!ex.StdOut.AtEndOfStream) out.push(ex.StdOut.ReadLine());
              while (ex.Status == 0) WScript.Sleep(20);
              out.Count = out.length; this.Output = out; this.ExitCode = ex.ExitCode;
            };
            function IPM_Dns() { this.Server = ""; }
            IPM_Dns.prototype.GetName = function (target, type) { return IPM_call("dns", target, type + "|" + this.Server); };
            function IPM_SnmpQuery() {
              this.Version = 2; this.PduType = 0xA0; this.Community = "public"; this.V3Security = "NoAuthNoPriv"; this.V3AuthMode = "SHA1";
              this.V3PrivMode = "AES"; this.V3UserName = ""; this.V3AuthPass = ""; this.V3PrivPass = ""; this.MaxRepetitions = 10; this.NonRepeaters = 0; this.oids = [];
            }
            IPM_SnmpQuery.prototype.AddOid = function (o) { this.oids.push(String(o)); };
            IPM_SnmpQuery.prototype.SetOid = function (o) { this.oids = o ? [String(o)] : []; };
            function IPM_Snmp() { this.Host = ""; this.Query = new IPM_SnmpQuery(); this.Reply = { ErrorStatus: 0, Items: [] }; this.Reply.Items.Count = 0; }
            IPM_Snmp.prototype.SendRequest = function () {
              var q = this.Query;
              var p = ["host=" + this.Host, "version=" + q.Version, "pdutype=" + q.PduType, "community=" + q.Community, "v3security=" + q.V3Security,
                "v3authmode=" + q.V3AuthMode, "v3privmode=" + q.V3PrivMode, "v3username=" + q.V3UserName, "v3authpass=" + q.V3AuthPass,
                "v3privpass=" + q.V3PrivPass, "maxrepetitions=" + q.MaxRepetitions, "nonrepeaters=" + q.NonRepeaters, "oids=" + q.oids.join(",")].join("\n");
              var lines = IPM_call("snmp", p, "").split("\n"), items = [];
              for (var i = 1; i < lines.length; i++) { var f = lines[i].split("\t"); if (f.length >= 3) items.push({ Oid: f[0], Type: parseInt(f[1], 10), Value: f.slice(2).join("\t") }); }
              items.Count = items.length;
              this.Reply = { ErrorStatus: parseInt(lines[0], 10), Items: items };
              return this.Reply.ErrorStatus == 0;
            };
            var Internal = { CreateObject: function (kind) {
              switch (String(kind).toLowerCase()) { case "process": return new IPM_Process(); case "dns": return new IPM_Dns(); case "snmp": return new IPM_Snmp(); }
              throw new Error("Unknown object '" + kind + "'. Use Process, DNS or SNMP.");
            } };
            // ---- user script ----

            """;
    }

    public static string Python(string current)
    {
        var families = string.Join(", ", RemoteFamilies.Select(f => $"'{f}'"));
        return $$"""
            # ---- IPMaster scripting API (generated) ----
            import sys as _ipm_sys
            def _ipm_hex(s): return str(s).encode('utf-16-be').hex().upper()
            def _ipm_unhex(h): return bytes.fromhex(h).decode('utf-16-be') if h else ''
            def _ipm_call(op, a='', b=''):
                _ipm_sys.stdout.write('@@IPM@@ %s %s %s\n' % (op, _ipm_hex(a), _ipm_hex(b))); _ipm_sys.stdout.flush()
                line = _ipm_sys.stdin.readline().rstrip('\r\n')
                if line.startswith('ok '): return _ipm_unhex(line[3:])
                raise RuntimeError(_ipm_unhex(line[4:]))
            class _IpmInput:
                Current = _ipm_unhex('{{current}}')
                def Column(self, name): return _ipm_call('column', name)
            class _IpmOutput:
                def Write(self, text):
                    _ipm_sys.stdout.write('@@IPM@@ out %s\n' % _ipm_hex(text)); _ipm_sys.stdout.flush()
            class _IpmRemote:
                _families = ({{families}})
                def __getattr__(self, family):
                    if family not in self._families: raise AttributeError('Remote.' + family + ' does not exist')
                    return lambda name: _ipm_call('remote', family, name)
            Input, Output, Remote = _IpmInput(), _IpmOutput(), _IpmRemote()
            # ---- user script ----

            """;
    }

    public static int LineCount(string prelude) => prelude.Count(c => c == '\n');
}
