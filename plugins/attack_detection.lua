--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  local util=require('util')

  -- setting for thresholding

  local settings={
    brute_force_request_threshold=5,
    invite_flood_threshold=3,
    message_flood_threshold=0
  }

  -- Object to get "from user" field value 
  local user=Field.new("sip.from.user")

  -- Object to get request/Status line
  local line=Field.new("sip.Request-Line")

  -- Object to get method used by sip
  local reg_method=Field.new("sip.Method")

  -- Object to get source IP Address
  local ip_src=Field.new("ip.src")

  -- Object to get Call-Id
  local call_id=Field.new("sip.Call-ID")

  -- Object to get Destination IP Address
  local ip_dst=Field.new("ip.dst")
  
  -- Object to get the from username
  local from_user=Field.new("sip.from.user")

  -- Object to get the to username
  local to_user=Field.new("sip.to.user")

  -- Object to get source mac
  local eth_src=Field.new("eth.src") 

  -- Object to get Destination mac
  local eth_dst=Field.new("eth.dst")

  -- Object to get status code
  local status_code=Field.new("sip.Status-Code")

  -- Object to get relative time of the current frame
  local time_relative=Field.new("frame.time_relative")

  -- Object to get Authorization Field
  local auth=Field.new("sip.Authorization")

  -- Object to get the frame number 
  local frame_number=Field.new("frame.number")

  -- Object to get crypto Field
  local media_attribute=Field.new("sdp.media_attribute.field")

  -- Table to store failed registers
  local failed_registers={}

  -- Table to store initial requests
  local initial_registers={}

  -- Table to store mac address 
  local mac_store={}

  -- Table to store MITM
  local mitm={}
  --Table to store mitm store
  local mitm_store={}
  
  -- Table to store unauthenticated users
  local unauthenticated={}

  -- Table to maintain lua keys
  local register_status={}

  -- Tables to maintain store
  local register_status_store={}
  local message_flood_store={}
  local invite_flood_store={}
  local invite_flood={}
  local message_flood={}
  
  local unauthenticated_store={}

  -- Tap to listen on frames with filter sip.Request-Line
  local tap = Listener.new("frame", "sip")

  -- Function to reset users table when new pcap is opened
  function tap.reset()
    register_status={}
    register_status_store={}
    initial_registers={}
    invite_flood={}
    invite_flood_store={}
    message_flood={}
    message_flood_store={}
    mac_store={}
    mitm={}
    mitm_store={}
    unauthenticated={}
    unauthenticated_store={}
    
  end

  -- This function will convert userdata to string
  local function getString(str)
    if(str()~=nil) then return tostring(str()) else return "" end
  end

  -- This function will be called for every packet
  function tap.packet(pinfo,tvb)


    -- variables to store source, destination, username, callid and methods
    local src=getString(ip_src)
    local dst=getString(ip_dst)
    local username=getString(from_user)
    local callId=getString(call_id)
    local method=getString(reg_method)

    -- For REGISTER method
    if(method=="REGISTER")
      then

          -- check whether the auth field exists.
          if(auth()==nil)
            then
                -- create an entry with current callId
                initial_registers[callId]=0
          else
              -- if auth field exists then it is not the first register request, therfore create an entry in register_status table
              local key=username.."@"..src.."-"..dst
              if(register_status[key]==nil)
                then


                table.insert(register_status_store,key)

                -- create entry and set requests = 1
                register_status[key]={}
                register_status[key]["user"]=username
                register_status[key]["source"]=src
                register_status[key]["destination"]=dst
                register_status[key]["requests"]=1
                register_status[key]["failed"]=0
                register_status[key]["success"]=false
                register_status[key]["startTime"]=tonumber(getString(time_relative))
                register_status[key]["endTime"]=tonumber(getString(time_relative))+1
              
              -- if entry already exists in table, update request by 1 and also update the time
              else
                register_status[key]["requests"]=register_status[key]["requests"]+1
                register_status[key]["endTime"]=tonumber(getString(time_relative))
              end   
          end 

    -- For INVITE method
    elseif(method=="INVITE")
      then

          -- defining key
          local key=username.."@"..src.."-"..dst
          
          -- flag to check whether crypto field exists or not
          local flag=false

          -- variable to fetch all the media attributes
          local mediaAttributes={media_attribute()}

          -- iterating over media attributes to check whether crypto field exists
          for k,v in pairs(mediaAttributes)do

            -- checking whether crypto field exists, if it exists then break the loop
            if (getString(v)=="crypto")
              then

                flag=true
                break
            end
          end
          
          -- check whether crypto field is there or not, if it is absent then the user is unautenticated
          if(not flag)
            then

            -- check whether entry exists in unauthenticated table
            if(unauthenticated[key]==nil)
              then

                table.insert(unauthenticated_store,key)
                unauthenticated[key]={}
                unauthenticated[key]["user"]=username
                unauthenticated[key]["source"]=src
                unauthenticated[key]["destination"]=dst
            end
          end

          

          -- create entry in invite_flood table and intialize count as 1
          if(invite_flood[key]==nil)
            then
                table.insert(invite_flood_store,key)
                invite_flood[key]={}
                invite_flood[key]["count"]=1
                invite_flood[key]["user"]=username
                invite_flood[key]["toUser"]=getString(to_user)
                invite_flood[key]["source"]=src
                invite_flood[key]["destination"]=dst
                invite_flood[key]["startTime"]=tonumber(getString(time_relative))
                invite_flood[key]["endTime"]=tonumber(getString(time_relative))+1

          -- if entry already exists increment count and update time
          else
              invite_flood[key]["count"]=invite_flood[key]["count"]+1
              invite_flood[key]["endTime"]=tonumber(getString(time_relative))
          end  

    -- For Message method.
    elseif(method=="MESSAGE")
      then
          local key=username.."@"..src.."-"..dst
          
          -- create an entry in message table
          if(message_flood[key]==nil)
            then
              
              table.insert(message_flood_store,key)

              message_flood[key]={}
              message_flood[key]["count"]=1
              message_flood[key]["user"]=username
              message_flood[key]["source"]=src
              message_flood[key]["destination"]=dst
              message_flood[key]["startTime"]=tonumber(getString(time_relative))
              message_flood[key]["endTime"]=tonumber(getString(time_relative))+1

          -- if entry already exists, update count and time
          else
              message_flood[key]["count"]=message_flood[key]["count"]+1
              message_flood[key]["endTime"]=tonumber(getString(time_relative))
          end

    -- if the status code is 401
    elseif(getString(status_code)=="401")
      then

          local key=username.."@"..dst.."-"..src

          -- if this is the first response to register request with no auth field then don't count it as failed request
          -- but if the value is not equal to zero then increment failed requests
          if(initial_registers[callId]~=nil and initial_registers[callId]~=0 and  register_status[key]~=nil)
            then
             register_status[key]["failed"]= register_status[key]["failed"]+1

          -- if the value is zero, increment it by one, so that next time we will know that the register request was not the first one
          elseif(initial_registers[callId]~=nil)
            then
              initial_registers[callId]=1
          end

    -- if the status code is 200 for the current call-id that means, the current status code belongs to the right chain, set sucess status to true 
    elseif(status_code=="200" and initial_registers[callId]==1)
      then
          local key=username.."@"..dst.."-"..src
          register_status[key]["success"]=true
    end

    -- For MITM Detection 
    -- create variables which will used later to store key, and mac addresses
    local key=""
    local s_src=""
    local s_dst=""
    local s_eth_src=""
    local s_eth_dst=""

    -- check whether the current sip packet is request or response
    -- data is stored with respect to who intiated the request, key is in the form : requester-responder
    if(line()~=nil)
      then

          -- if it a request line, assign key as source and destination, store the mac in similar way
          key=src.."-"..dst  
          s_eth_src=getString(eth_src)
          s_eth_dst=getString(eth_dst)
          s_src=src
          s_dst=dst    
          
    else
          -- if it's a status line, assign key as destination-source, store the destination mac in source and vice versa
          
          key=dst.."-"..src
          s_eth_src=getString(eth_dst)
          s_eth_dst=getString(eth_src)
          s_src=dst
          s_dst=src
    end

    -- check whether data about the source destination pair have been stored, if not store their mac addresses
    if(mac_store[key]==nil)
      then

        mac_store[key]={}
        mac_store[key]["src"]=s_eth_src
        mac_store[key]["dst"]=s_eth_dst

    -- if data already exists, check whether current mac is equal to the stored mac
    else
        
        -- match current mac and stored mac, if there is a mismatch, then it is mitm and create a entry in mitm table
        if(mac_store[key]["src"]~=s_eth_src or mac_store[key]["dst"]~=s_eth_dst)
          then

            if(mitm[key]==nil) then
              table.insert(mitm_store,key)
              mitm[key]={}
              mitm[key]["src"]=s_src
              mitm[key]["dst"]=s_dst

              -- store the mismatched macs in mitm table
              mitm[key]["src_mac"]=mac_store[key]["src"]..","..s_eth_src
              mitm[key]["dst_mac"]=mac_store[key]["dst"]..","..s_eth_dst
              mitm[key]["attacker_mac"]=mac_store[key]["dst"]
            end
        end
    end  
  end

    -- Print table for brute forcing attempts
    local function brute_force(win,stringToFind)

           -- Create a new Window with "SIP Extensions Title"
          local header=  " __________________________________________________________________________________________________________________________________\n"
                       .."|   S.no   | Attacker Machine | Target Extension | Target Machine |    Requests Sent    |  Failed Attempts |  Requests Per second  |\n"

          
          win:set(header)
          local count=0
          for k,v in ipairs(register_status_store)do          
              
            data=register_status[v]

            -- all of the strings forming a table is passed to searchStr function, which then searches for the string toFind 
            if(util.searchStr({data["source"],data["user"],data["destination"],data["requests"],data["failed"],string.format("%.02f",data["requests"]/(data["endTime"]-data["startTime"]))},stringToFind))
              then
                if(data["requests"]>settings.brute_force_request_threshold)
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
                        ["value"]=data["source"],
                        ["length"]=18,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["user"],
                        ["length"]=18,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["destination"],
                        ["length"]=16,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["requests"],
                        ["length"]=21,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["failed"],
                        ["length"]=18,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=string.format("%.02f",data["requests"]/(data["endTime"]-data["startTime"])),
                        ["length"]=23,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      }                             
                    }
                    win:append("|----------------------------------------------------------------------------------------------------------------------------------|\n")        
                    win:append(acf(acf_settings,"|"))  
                end
            end
        end
          win:append("|__________________________________________________________________________________________________________________________________|\n")     
    end

      -- Print Table for Message Flooding.
      local function message_flooding(win,stringToFind)
    

        local header=  " ____________________________________________________________________________________________\n"
                     .."|   S.no   | Attacker Machine | Target Machine |    Messages Sent    |  Messages Per second  |\n"

        
        win:set(header)
        local count=0
        for k,v in pairs(message_flood_store)do      

          data=message_flood[v]

          if(util.searchStr({data["source"],data["destination"],data["count"],string.format("%.02f",data["count"]/(data["endTime"]-data["startTime"]))},stringToFind))    
              then
                if(data["count"]>settings.message_flood_threshold)
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
                        ["value"]=data["source"],
                        ["length"]=17,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["destination"],
                        ["length"]=17,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["count"],
                        ["length"]=21,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=string.format("%.02f",data["count"]/(data["endTime"]-data["startTime"])),
                        ["length"]=23,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      }                             
                    }
                    win:append("|--------------------------------------------------------------------------------------------|\n")        
                    win:append(acf(acf_settings,"|"))  
                end
          end
        end
        win:append("|____________________________________________________________________________________________|\n")     
    end

      -- Print table for invite flooding.
      local function invite_flooding(win,stringToFind)
    
        local header=  " ___________________________________________________________________________________________________________________________________\n"
                     .."|   S.no   | Attacker Machine | Attacker Extension | Target Extension | Target Machine |    Invites Sent    |   Invites Per second  |\n"

        
        win:set(header)
        local count=0
        for k,v in ipairs(invite_flood_store)do          
            
            data=invite_flood[v]

            if(util.searchStr({data["source"],data["user"],data["toUser"],data["destination"],data["count"],string.format("%.02f",data["count"]/(data["endTime"]-data["startTime"]))},stringToFind))
              then
                if(data["count"]>settings.invite_flood_threshold)
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
                        ["value"]=data["source"],
                        ["length"]=18,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["user"],
                        ["length"]=20,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },

                      { 
                        ["value"]=data["toUser"],
                        ["length"]=18,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["destination"],
                        ["length"]=16,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=data["count"],
                        ["length"]=20,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      },
                      { 
                        ["value"]=string.format("%.02f",data["count"]/(data["endTime"]-data["startTime"])),
                        ["length"]=23,
                        ["delimiter"]="",
                        ["next"]=true,
                        ["branch"]=false
                      }                             
                    }
                    win:append("|-----------------------------------------------------------------------------------------------------------------------------------|\n")        
                    win:append(acf(acf_settings,"|"))  
                end
            end
        end
        win:append("|___________________________________________________________________________________________________________________________________|\n")     
    end

    -- Print table for unauthenticated users
    local function unauthenticated_users(win,stringToFind)
    
        local header=  " ______________________________________________________________\n"
                     .."|   S.no   |   Call Source   |   Username   | Call Destination |\n"

        win:set(header)
        local count=0
        for k,v in ipairs(unauthenticated_store)do          
            data=unauthenticated[v]
            
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
                    ["value"]=data["source"],
                    ["length"]=17,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=data["user"],
                    ["length"]=14,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=data["destination"],
                    ["length"]=18,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  }                          
                }
                win:append("|--------------------------------------------------------------|\n")        
                win:append(acf(acf_settings,"|"))  
            end
        end
        win:append("|______________________________________________________________|\n")     
end
    

      -- Print table for MITM attempts
      local function mitm_attempts(win,stringToFind)
  
        local header=  " ________________________________________________________________________________________________________________\n"
                     .."|   S.no   |    Call Source   |   Call Destination   |     Source Mac     |   Destination Mac  |  Attacker Mac   |\n"

        win:set(header)
        local count=0
        for k,v in pairs(mitm_store)do   
          data=mitm[v]

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
                    ["value"]=data["src"],
                    ["length"]=18,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=data["dst"],
                    ["length"]=22,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=data["src_mac"],
                    ["length"]=20,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=data["dst_mac"],
                    ["length"]=20,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=data["attacker_mac"],
                    ["length"]=17,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  }                             
                }
                win:append("|----------------------------------------------------------------------------------------------------------------|\n")        
                win:append(acf(acf_settings,"|"))  
          end
        end
        win:append("|________________________________________________________________________________________________________________|\n")     
    end


  -- Functions to call print table functions.

  local function menu1()
      util.dialog_menu(brute_force,"Brute Force")
  end

  local function menu2()
      util.dialog_menu(message_flooding,"Message Flooding")
  end

  local function menu3()
      util.dialog_menu(invite_flooding,"Invite Flooding")
  end

  local function menu4()
      util.dialog_menu(mitm_attempts,"MITM Attempts")
  end

  local function menu5()
      util.dialog_menu(unauthenticated_users,"Unauthenticated Users")
  end

  -- Register the function to Tools menu
  register_menu("VOIP/VOIP Attack Detection/Brute Force",menu1, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/VOIP Attack Detection/Message Flooding",menu2, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/VOIP Attack Detection/Invite Flooding",menu3, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/VOIP Attack Detection/MITM Attempts",menu4, MENU_TOOLS_UNSORTED)
  register_menu("VOIP/VOIP Attack Detection/Unauthenticated Users",menu5, MENU_TOOLS_UNSORTED)

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
        c=0
        global["value"]=str:sub(a+c)
        global["next"]=true
        return format_str(global,str:sub(1,a-1))
    end
    return s
end

