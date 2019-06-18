--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  local util=require('util')

  -- Object to get "contact.user" field value is the extension for request line
  local contact_extension=Field.new("sip.contact.user")

  -- Object to get "to.user" field value, in status line as extension
  local to_extension=Field.new("sip.to.user")

  -- Object to get "to.user" field value, in status line as extension
  local from_extension=Field.new("sip.from.user")

  -- Object to get the username
  local user= Field.new("sip.display.info")

  local from_host=Field.new("sip.from.host")

  -- Object to get the ip address of the host
  local contact_host=Field.new("sip.contact.host")

  -- Object to get the ip address of the host
  local to_host=Field.new("sip.to.host")

  -- Object to get user agent
  local user_agent=Field.new("sip.User-Agent")

  -- Table to store unique users
  local users={}

  -- Table to store server information
  local server={}

  -- Table to store hashcat hashs
  local digests={}

  -- Object to get the method that is being used
  local method=Field.new("sip.Method")

  -- Object to get request uri
  local request_uri=Field.new("sip.r-uri.host")

  -- Object to get source IP Address
  local ip_src=Field.new("ip.src")

  -- Object to get Destination IP Address
  local ip_dst=Field.new("ip.dst")

  -- Object to get source port 
  local src_port=Field.new("udp.srcport")

  -- Object to get destination port
  local dst_port=Field.new("udp.dstport")
  
  -- Object to get request/status line
  local line=Field.new("sip.Request-Line")

  -- Object to get Status-Code
  local status_code=Field.new("sip.Status-Code")

  -- Object to get digest response
  local digest=Field.new("sip.auth.digest.response")

  -- Object to get username
  local auth_username=Field.new("sip.auth.username")
  
  -- Object to get realm
  local realm= Field.new("sip.auth.realm")
  
  -- Object to get nonce 
  local nonce=Field.new("sip.auth.nonce")

  -- Object to get uri
  local uri=Field.new("sip.auth.uri")

  -- Object to get cnonce
  local cnonce=Field.new("sip.auth.cnonce")

  -- Object to get nonce count
  local nonce_count=Field.new("sip.auth.nc")
  
  -- Object to get qop
  local qop=Field.new("sip.auth.qop")

  -- Object to get algo
  local algo=Field.new("sip.auth.algorithm")

  -- Object to get opaque
  local opaque=Field.new("sip.auth.opaque")

  -- Object to get offset of P-Asserted-Identity
  local p_asserted_identity=Field.new("sip.P-Asserted-Identity")

  -- Object to get pai user
  local pai_user=Field.new("sip.pai.user")

  -- Object to get offset of From 
  local from_offset=Field.new("sip.From")

  -- Object to get offset of To
  local to_offset=Field.new("sip.To")

  -- Object to get offset of Contact
  local contact_offset=Field.new("sip.Contact")

  -- Tap to listen on frames with filter sip.Request-Line
  local tap = Listener.new("frame", "sip")

  -- Object to get Server field
  local sip_server=Field.new("sip.Server")

  -- Object to get frame number
  local frame_number=Field.new("frame.number")


  local users_store={}
  local digests_store={}
  local server_store={}

  -- Function to convert userdata to string
  function getString(str)
   if(str()~=nil) then local a= tostring(str()):gsub("\"","") return a else return "NA" end
  end

  -- Function to reset users table when new pcap is opened
  function tap.reset()
    users={}
    digests={}
    server={}
    users_store={}
    digests_store={}
    server_store={}
  end

  -- This function will be called for every packet
  function tap.packet(pinfo,tvb)

      -- storing extension in ext variable
      local ext=""

      -- storing the host name
      local host_name=""



      -- getting username, if it exists
      local username=getString(user)
      local usernames={user()}

      -- store useragernt
      local agent=getString(user_agent)

      local src=getString(ip_src)
      local dst=getString(ip_dst)
      local fromExtension=getString(from_extension)
      local toExtension=getString(to_extension)
      local contactExtension=getString(contact_extension)

      -- If method is REGISTER, store the server in server table
      if(getString(method)=="REGISTER")
        then
            -- if an entry doesn't exist in server table create one
            if(server[getString(request_uri)]==nil) then 
              table.insert(server_store,getString(request_uri))
              server[getString(request_uri)]={}
              server[getString(request_uri)]["User-Agent"]="NA"
            end

            if(digest()~=nil)
              then
              
              -- store digest in a variable
              local msgDig=getString(digest())

              -- if entry doesnt exist in digest table create one, and store the diggest is the required manner
              if(digests[msgDig]==nil and auth_username()~=nil and realm()~=nil and uri~=nil and nonce()~=nil and cnonce()~=nil and nonce_count()~=nil and qop()~=nil and algo()~=nil)
                  then
                       table.insert(digests_store,msgDig)
                      digests[msgDig]={}
                      digests[msgDig]["src"]=src
                      digests[msgDig]["dst"]=getString(ip_dst)

                      digests[msgDig]["username"]=getString(auth_username())
                      digests[msgDig]["forHashCat"]="$sip$***"
                                                     ..getString(auth_username()).."*"
                                                     ..getString(realm()).."*REGISTER*sip*"
                                                     ..getString(uri()):gsub("sip:","")   .."**"
                                                     ..getString(nonce()).."*"
                                                     ..getString(cnonce()).."*"
                                                     ..getString(nonce_count()).."*"
                                                     ..getString(qop()).."*"
                                                     ..getString(algo()):upper().."*"
                                                     .. getString(digest())

              end
            end
      end

      local createServer=false
      local serverAgent=""

      -- Identify server
      if(sip_server()~=nil )
        then
          createServer=true
          serverAgent=sip_server().value

      elseif(p_asserted_identity()~=nil)
        then
          createServer=true
          serverAgent=agent
      else
        serverAgent=agent
      end

      -- If the source ip is of server.
      if(createServer)
        then
           if(server[src]==nil) 
              then     
                table.insert(server_store,src)
                server[src]={} 
                server[src]["User-Agent"]=serverAgent

           end
      end

      -- Store the User-Agent for client
      if(server[src]~=nil and server[src]["User-Agent"]=="NA") then     
              server[src]["User-Agent"]=serverAgent
      end

       if(server[src]~=nil)
                  then
                
                   local key=fromExtension.."@"..src
                   if(users[key]==nil and fromExtension~="NA")
                    then
                    table.insert(users_store,key)
                    users[key]={}
                    users[key]["extension"]=fromExtension
                    users[key]["username"]="NA"
                    users[key]["host"]="NA"
                    users[key]["agent"]="NA"
                    
                  end
                  key=toExtension.."@"..src
                  if(users[key]==nil and toExtension~="NA")
                    then
                    
                    table.insert(users_store,key)
                    users[key]={}
                    users[key]["extension"]=toExtension
                    users[key]["username"]="NA"
                    users[key]["host"]="NA"
                    users[key]["agent"]="NA"

                  end
      end

    -- Map the username, extension, IP address and user agent of the client. 
    if(server[dst]~=nil and server[src]==nil)
      then

           if(line()~=nil)
              then
                
                if(getString(method)=="INVITE")
                  then
                
                   local key=fromExtension.."@"..dst
                   if(users[key]==nil and fromExtension~="NA")
                    then

                    table.insert(users_store,key)
                    users[key]={}
                    users[key]["extension"]=fromExtension
                    users[key]["username"]="NA"
                    users[key]["host"]=src
                    users[key]["agent"]=agent
                    
                  end
                  key=toExtension.."@"..dst
                  if(users[key]==nil and toExtension~="NA")
                    then
                    
                    table.insert(users_store,key)
                    users[key]={}
                    users[key]["extension"]=toExtension
                    users[key]["username"]="NA"
                    users[key]["host"]="NA"
                    users[key]["agent"]="NA"

                  end
                
                -- for all request except invites
                else
                  local key=fromExtension.."@"..dst
                  if(users[key]==nil and fromExtension~="NA")
                    then

                    table.insert(users_store,key)
                    users[key]={}
                    users[key]["extension"]=fromExtension
                    users[key]["username"]="NA"
                    users[key]["host"]=src
                    users[key]["agent"]=agent
                  elseif(fromExtension~="NA" and users[key]["agent"]=="NA")
                    then
                    users[key]["agent"]=agent
                  end
                end
           elseif(getString(status_code)=="200")
              then
                local key=toExtension.."@"..dst
                if(users[key]~=nil)
                  then

                  if(users[key]["host"]=="NA")
                    then
                    users[key]["host"]=src
                  end
                  if(users[key]["agent"]=="NA")
                    then
                    users[key]["agent"]=agent
                  end
                end
          
          end
      else

         
          if(p_asserted_identity()~=nil and #usernames~=0)
            then
              if(p_asserted_identity().offset<usernames[#usernames].offset)
                then

                  local key=pai_user().value.."@"..src
                  if(users[key]~=nil and users[key]["username"]=="NA")
                    then
                           
                    users[key]["username"]=getString(usernames[#usernames])
                  end
              end
          end

          for k,value in ipairs(usernames) do
            
            if(from_offset().offset<value.offset and from_host().offset>value.offset and fromExtension~="NA")
              then
                local key=from_extension().value.."@"..src
                if(users[key]~=nil and users[key]["username"]=="NA")
                  then
                  users[key]["username"]=getString(value)
                end
            elseif(to_offset().offset<value.offset and to_host().offset>value.offset and toExtension~="NA")
              then
                local key=to_extension().value.."@"..src
                if(users[key]~=nil and users[key]["username"]=="NA")
                  then
                  users[key]["username"]=getString(value)
                end
            elseif(contact_offset()~=nil and contactExtension~="NA")
              then
                if(contact_offset().offset<value.offset and contact_host().offset>value.offset)
                  then
                    local key=contact_extension().value.."@"..src
                    if(users[key]~=nil and users[key]["username"]=="NA")
                      then
                      users[key]["username"]=getString(value)
                    end
                end
            end
          end

    end

  end

  -- Function to print extensions table 
  local function extensions(win,stringToFind)
  
      local header=  " ________________________________________________________________________________________\n"
                   .."|   S.no   |   Extension   |    Username    |       Host       |        User Agent       |\n"

      win:set(header)
      local count=0
      local unique_users={}
      for k,v in ipairs(users_store)do        
          data=users[v]
          print(v)
          if(unique_users[data["extension"].."@"..data["host"]]==nil)
          then
          unique_users[data["extension"].."@"..data["host"]]=true

          if(util.searchTable(data,stringToFind))
            then

            count=count+1
            local acf_settings={
              { 
                ["value"]=count,           
                ["length"]=10,  
                ["delimiter"]="",                 
                ["next"]=true,
                ["branch"]=false                     
              },
              { 
                ["value"]=data["extension"],
                ["length"]=15,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["username"],
                ["length"]=16,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["host"],
                ["length"]=18,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["agent"],
                ["length"]=25,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              }                            
            }
            win:append("|----------------------------------------------------------------------------------------|\n")        
            win:append(acf(acf_settings,"|"))  
          end
        end
      end
      win:append("|________________________________________________________________________________________|\n")     
  end

    -- Function to print servers and proxy table  
  local function servers_proxy(win,stringToFind)
  
      local header=  " ___________________________________________________________\n"
                   .."|   S.no   |   Server/Proxy IP   |        User Agent       |\n"

      win:set(header)
      local count=0
      for k,v in ipairs(server_store)do
          data=server[v]

          if(util.searchStr({v,data["User-Agent"]},stringToFind))
            then
            count=count+1
            local acf_settings={
              { 
                ["value"]=count,           
                ["length"]=10,  
                ["delimiter"]="",                 
                ["next"]=true,
                ["branch"]=false                     
              },
              { 
                ["value"]=v,
                ["length"]=21,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["User-Agent"],
                ["length"]=25,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              }                         
            }
            win:append("|----------------------------------------------------------|\n")        
            win:append(acf(acf_settings,"|"))
          end  
      end
      win:append("|__________________________________________________________|\n")     
  end

  -- Function to print sip auth export information.
  local function sip_auth_export(win,stringToFind)


      local header=  " __________________________________________________________________________________________________________\n"
                   .."|   S.no   |   username   |     Client IP      |       Server IP    |              Message Digest          |\n"   
      win:set(header)
      local count=0
      for k,v in pairs(digests_store)do           -- <- table whoes data you wana print
          data=digests[v]
          if(util.searchStr({v,data["username"],data["src"],data["src"],data["forHashCat"]},stringToFind))
            then
                count=count+1
                local acf_settings={
                { 
                  ["value"]=count,           
                  ["length"]=10,  
                  ["delimiter"]="",                 
                  ["next"]=true,
                  ["branch"]=false                     
                },
                { 
                  ["value"]=data["username"],
                  ["length"]=14,
                  ["delimiter"]="",
                  ["next"]=true,
                  ["branch"]=false
                },
                { 
                  ["value"]=data["src"],
                  ["length"]=20,
                  ["delimiter"]="",
                  ["next"]=true,
                  ["branch"]=false
                },
                { 
                  ["value"]=data["dst"],
                  ["length"]=20,
                  ["delimiter"]="",
                  ["next"]=true,
                  ["branch"]=false
                },
                { 
                  ["value"]=v,
                  ["length"]=38,
                  ["delimiter"]="",
                  ["next"]=true,
                  ["branch"]=false
                }                               
              }
                win:append("|----------------------------------------------------------------------------------------------------------|\n")        
                win:append(acf(acf_settings,"|"))  
          
            win:append(data["forHashCat"])
            win:append("\n")
          end
    end
    win:append("|__________________________________________________________________________________________________________|\n")     

  end 

-- Functions to call print table functions.
  function menu1()
    util.dialog_menu(extensions,"Extensions")
  end
  function menu2()
    util.dialog_menu(servers_proxy,"Servers and Proxy")
  end
  function menu3()
    util.dialog_menu(sip_auth_export,"SIP Auth Export")
  end

  -- Register the function to Tools menu
  register_menu("VOIP/SIP Information Gathering/Extensions",menu1, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/SIP Information Gathering/Servers and Proxy",menu2, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/SIP Information Gathering/SIP Auth Export",menu3, MENU_TOOLS_UNSORTED)
end

-- Functions to prettify output.

function acf(settings,column_seperator)
  local final=""
  while(isNext(settings))do
      for k,v in ipairs(settings)do
          if(v["next"]==false) then v["value"]="" else v["next"]=false end
          final=final..column_seperator..format_str(v)
          if(k==#settings) then final=final..column_seperator.."\n" end
      end
   end
  return final
end

function isNext(settings)
  for k,v in ipairs(settings)do 
    if(v["next"]) then return true end
  end
  return false
end

function format_str(global,substr)
    local m=0
    local n=0
    local str=""
    local len=global["length"]
    local delimiter=global["delimiter"]
    if(substr==nil) then str=global["value"] else str=substr end
    if(str==nil) then str="" else str=tostring(str) end
    if (len==nil) then len=0 end
    if(delimiter==nil) then delimiter="" end
    local s=str
    if(str:len()<len)
        then
        if((len-str:len())%2==0)
            then 
                m=(len-str:len())/2
                n=m
        else
                m=math.floor(((len-str:len()) /2))+1
                n=m-1
        end     
        for i=1, m
            do
            s=" "..s
        end
        for i=1, n
            do
            s=s.." "
        end
    elseif(str:len()>len)
        then
        local str2=""
        local a=len
        if(global["branch"]) then str2=""..delimiter.."[^"..delimiter.."]" else str2=""..delimiter.."[^"..delimiter.."]*$" end
        if(delimiter~="")
            then
             a=string.find(str:sub(0,len), str2)
         end
        local c=0
        if( a==nil or a>len) then a=len else c=1 end
        global["value"]=str:sub(a+c)
        global["next"]=true
        return format_str(global,str:sub(1,a-1))
    end
    return s
end

