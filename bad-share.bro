@load base/frameworks/files
@load base/frameworks/notice
@load policy/protocols/smb

export {
    redef enum Notice::Type += {
        Match
    };

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
{

if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
{
NOTICE([$note=Match, $msg=fmt("Potentially Malicious Use of an Administative Share"), $sub=fmt("%s",path), $conn=c]);
}
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
{
if ("IPC$" in path || "ADMIN$" in path || "C$" in path)
{
NOTICE([$note=Match, $msg=fmt("Potentially Malicious Use of an Administative Share"), $sub=fmt("%s",path), $conn=c]);
}
}

}
