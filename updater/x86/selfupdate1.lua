
--[[
    Software and Content Update
    TODO : Add Logging
--]]


-- Set up library path
local current_path = cpp_getDirInstallRoot()
package.path = package.path .. ";" .. current_path .. "/data/lib/?.lua"
local data_path = cpp_getDirSystemRoot() .. "\\"

-- Load libraries
local log = require "log"
local utils = require "utils"
local cloudutils = require "cloudutils"

-- Static constants
local SELF_UPDATE_TIMEOUT = cpp_getConfigValue("LCA_Updater.auto_update.http_timeout", 30)
local UPDATE_CLOUD_URL = cpp_getConfigValue("LCA_Updater.auto_update.cloud_url", "http://aapi-sec-epp.xiaojukeji.com")
local UPDATE_INTERVAL = cpp_getConfigValue("LCA_Updater.auto_update.check_interval", 3600)
local UPLOAD_RETRY_ATTEMPT =  cpp_getConfigValue("LCA_Updater.upload_retry_attempt", 10)
local UPLOAD_RETRY_DELAY =  cpp_getConfigValue("LCA_Updater.upload_retry_delay", 10)
local SEC_MS = 1000
local MINS_IN_MS = SEC_MS*60
local HOURS_IN_MS = MINS_IN_MS*60
local HOURS_IN_SECS = 60*60

-- AV Update Constants
local avInstallRoot
local avDefTargetFolder
local avDownloadTmpFolder


local AV_CACHE_DIR_NAME = ".tmp"
local AV_LOCAL_CACHE_FILE_NAME = ".cache"
local AV_SIG_DIR_NAME = "avl"

local AV_UPDATE_URL = cpp_getConfigValue("LCA_Updater.av_update.url", "http://aapi-sec-epp.xiaojukeji.com")
local AV_HTTP_RETRIES = cpp_getConfigValue("LCA_Updater.av_update.retries", 5)
local AV_HTTP_RETRY_DELAY = cpp_getConfigValue("LCA_Updater.av_update.retry_delay", 10)
local AV_HTTP_TIMEOUT = cpp_getConfigValue("LCA_Updater.av_update.http_timeout", 120)
local AV_REG_KEY = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LCAMon"
local AV_UNLOAD_NAME = "Unload"
local AV_WORK_DONE_NAME = "avlworkdone"


function compareVersion(current, new)
    local itc = string.gmatch(current,"%d+")
    local itn = string.gmatch(new,"%d+")

    while true do
        local subC = itc()
        local subN = itn()
        if subC == nil and subN == nil then
            break
        else
            subC = subC and tonumber(subC) or 0
            subN = subN and tonumber(subN) or 0
            if subN > subC then
                return true
            elseif subC > subN then
                return false
            end
        end
    end
    return false
end

function GetLastDownloadedPart(pkgType, version)
    local val_name = pkgType .. "_" .. version .. "_last_downloaded_part"
    local last_downloaded_part = cpp_storageGet("general", val_name)
    if last_downloaded_part == nil or last_downloaded_part == '' then return nil else return tonumber(last_downloaded_part) end
end

function SetLastDownloadedPart(pkgType, version, last_downloaded_part)
    local val_name = pkgType .. "_" .. version .. "_last_downloaded_part"
    cpp_storageSet("general", val_name, tostring(last_downloaded_part))
end

function getLastCustomPackageVersion()
    local val_name = "last_custom_pkg_version"
    local last_custom_pkg_ver = cpp_storageGet("general", val_name)
    if last_custom_pkg_ver == nil or last_custom_pkg_ver == '' then return '' else return last_custom_pkg_ver end
end

function setLastCustomPackageVersion(custom_pkg_ver)
    local val_name = "last_custom_pkg_version"
    cpp_storageSet("general", val_name, custom_pkg_ver)
end

local function isFile(name)
    local f = io.open(name,"r")
    if f ~= nil then
        io.close(f)
        return true
    else
        return false
    end
end

local function getFileSize(fd)
   local current = fd:seek()
   local size = fd:seek("end")
   fd:seek("set", current)
   return size
end

function verifyDownloadedParts(pkgType, version, download_folder)
    -- get last downloaded part from db
    local lastDownloadedPart = GetLastDownloadedPart(pkgType, version)
    if lastDownloadedPart == nil then
        log.debug("New download for pkgType:" .. pkgType .. " version:" .. version .. " folder:" .. download_folder)
        return 0
    end

    local next = 0
    local last_successful_part = 0
    while next <= lastDownloadedPart do
        local dst = download_folder .. tostring(next)
        if not isFile(dst) then
            log.error("File: " .. dst .. " Not present!")
            return last_successful_part
        end
        last_successful_part = next
        next = next + 1
    end
    log.debug("last successful downloaded part :" .. lastDownloadedPart)
    return lastDownloadedPart
end

local function copyToFile(src_path, out_fd)
    local fd, err = io.open(src_path, "rb")
    if not fd then
        log.error("Error opening file :" .. src_path .. " Error:" .. err)
        return false
    end

    local data = fd:read("*all")
    out_fd:write(data)
    fd:close()
    return true
end

function isPackageDownloaded(pkgType, dst, version)
    if not isFile(dst) then
        return false
    end
    local val_name = pkgType .. "_" .. version .. "_download"
    local local_file_size = cpp_getFileSize(dst)

    local db_file_size = cpp_storageGet("general", val_name)
    if db_file_size == nil or local_file_size ~= db_file_size then return false else return true end
end

function saveDownloadState(pkgType, dst, version)
    local val_name = pkgType .. "_" .. version .. "_download"
    local downloaded_file_size = cpp_getFileSize(dst)
    if downloaded_file_size == 0 then
        log.error("Invalid file downloaded. pkgType:" .. pkgType .. " dest:" .. dst .. " version:" .. version)
        return false
    end
    cpp_storageSet("general", val_name, tostring(downloaded_file_size))
    return true
end


function downloadPackageInPartsHelper(pkgType, resource, folder, final_dst, version, cdn_url, total_parts, file_size)
    local download_folder = folder .. pkgType .. "_" .. version ..  "\\"
    createDir(download_folder)

    log.debug("Downloading PARTS")
    log.debug("pkgType:" .. pkgType)
    log.debug("resource:" .. resource)
    log.debug("folder:" .. folder)
    log.debug("final_dst:" .. final_dst)
    log.debug("version:" .. version)
    log.debug("file_size:" .. file_size)

    if cdn_url ~= nil then
        log.debug("cdn_url:" .. cdn_url)
    end

    log.debug("Downloading PARTS to local dest :" .. download_folder)
    local nextPart = verifyDownloadedParts(pkgType, version, download_folder)
    log.debug("Next part to download :" .. nextPart)
    while nextPart < total_parts do
        local dst = download_folder .. tostring(nextPart)
        log.debug("Downloading part [" .. nextPart .."] to local dest :" .. dst)
        local request_data
        local download_url
        if cdn_url ~= nil then
            download_url = cdn_url .. "/" .. resource
        else
            download_url = UPDATE_CLOUD_URL .. "/aapi/v1/selfUpdate/downloadpartial/" .. resource
        end
        download_url = download_url .. tostring(nextPart)
        log.debug("Download url :" .. download_url)

        request_data = {
            url = download_url,
            method = "GET",
            headers = {
                ["X-AAPI-TOKEN"] = token
            },
            downloadToFile = dst,
            http_timeout =  SELF_UPDATE_TIMEOUT,
            retry_delay = UPLOAD_RETRY_DELAY,
            max_retry_attempts = UPLOAD_RETRY_ATTEMPT
        }

        local code, response = cpp_httpsWrapper(request_data)
        if code ~= 200 or not isFile(dst) then
            log.error("Failed to download from url :" .. download_url .. ", dest:" .. dst)
            return code
        end

        log.debug("Download successfully to :" .. dst)

        -- set last downloaded part in db
        SetLastDownloadedPart(pkgType, version, nextPart)
        nextPart = nextPart + 1
    end

    -- All parts are downloaded.. now combine all parts into 1 file with path final_dst
    local out_fd, out_err = io.open(final_dst, "wb")
    if not out_fd then
        log.error("Failed to open file:" .. final_dst .." for writing. err :" .. out_err)
        return 402
    end

    nextPart = 0
    while nextPart < total_parts do
        local src = download_folder .. tostring(nextPart)
        if not copyToFile(src, out_fd) then
            out_fd:close()
            return 402
        end
        nextPart = nextPart + 1
    end
    out_fd:close()

    local downloaded_file_size = cpp_getFileSize(final_dst)
    log.debug("Total file size downlaoded :" .. downloaded_file_size)
    if file_size ~= downloaded_file_size then
        log.error("Cloud file size :" .. file_size .. " Downloaded file size :" .. downloaded_file_size)
        return 402
    end

    log.debug("Successfully saved to :" .. final_dst)

    -- Delete all parts files
    nextPart = 0
    while nextPart < total_parts do
        local file_path = download_folder .. tostring(nextPart)
        log.debug("Deleting part :" .. file_path)
        os.remove(file_path)
        nextPart = nextPart + 1
    end
    saveDownloadState(pkgType, final_dst, version)
    return 200,{true}
end

function downloadPackageHelper(pkgType, resource, folder, dst, version, cdn_url, partial_download_location, total_parts, file_size)
    -- check if the package was already downloaded
    if isPackageDownloaded(pkgType, dst, version) then
        log.debug("Package " .. pkgType .. " already downloaded. version:" .. version)
        return 200,{true}
    end
    if partial_download_location ~= nil and total_parts ~= nil then
        return downloadPackageInPartsHelper(pkgType, partial_download_location, folder, dst, version, cdn_url, total_parts, file_size)
    end

    log.debug("Downloading FULL")
    log.debug("pkgType:" .. pkgType)
    log.debug("resource:" .. resource)
    log.debug("folder:" .. folder)
    log.debug("dst:" .. dst)
    log.debug("version:" .. version)

    local request_data
    local download_url
    if cdn_url ~= nil then
        log.debug("cdn_url:" .. cdn_url)
        download_url = cdn_url .. "/" .. resource
    else
        download_url = UPDATE_CLOUD_URL .. "/aapi/v1/selfUpdate/download/" .. resource
    end
    request_data = {
        url = download_url,
        method = "GET",
        headers = {
            ["X-AAPI-TOKEN"] = token
        },
        downloadToFile = dst,
        http_timeout =  SELF_UPDATE_TIMEOUT,
        retry_delay = UPLOAD_RETRY_DELAY,
        max_retry_attempts = UPLOAD_RETRY_ATTEMPT
    }

    local  code, response = cpp_httpsWrapper(request_data)
    if code == 200 then
        -- save downloaded state to db
        saveDownloadState(pkgType, dst, version)
        return code,{true}
    else
        return code
    end
end


function getCloudVersion(profile, packageType, version)
    local arch
    if system_profile["arch"] == 64 or system_profile["arch"] == "x64" then
        arch = "x64"
    else
        arch = "x86"
    end            
    local data = '{"agentUuid":"' .. system_profile["agent_id"] .. '","platform":"' .. system_profile["platform"] .. '","architecture":"' .. arch .. '","profile":"' .. profile .. '","product":"' .. packageType .. '","version":"' .. version .. '"}'
    local out = {}
    local request_data
    request_data = {
        url = UPDATE_CLOUD_URL .. '/aapi/v1/selfUpdate/meta',
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["X-AAPI-TOKEN"] = token,
            ["Content-Length"] = data:len()
        },
        data = data,
        http_timeout =  SELF_UPDATE_TIMEOUT,
        retry_delay = UPLOAD_RETRY_DELAY,
        max_retry_attempts = UPLOAD_RETRY_ATTEMPT
    }

    local code, response = cpp_httpsWrapper(request_data)
    if code == 200 then
        local metaJson = utils.json_decode(response)
        if metaJson ~= nil and type(metaJson) == "table" and metaJson["latest_version"] ~= nil then
            return code, {string.match(metaJson["latest_version"],"%d+%.%d+%.%d+"), metaJson["resource_location"], metaJson["cdn_url"], metaJson["partial_download_location"], metaJson["total_parts"], metaJson["file_size"]}
        else
            log.error("Invalid version/resource_location")
        end
    else
        return code
    end

end

function notifyNetworkChangeToCloud(profile, start_time, bios_id, os_id, system_id, disk_id, os_version, hostname, mac_list, cpu, memory)
    log.debug("notifyNetworkChangeToCloud Enter")
    -- block until agent_id is loaded from storage
    system_profile["agent_id"] = cpp_storageGetBlocking("general", "AGENT_UUID")

    -- setup system_profile
    system_profile["start_time"] = start_time
    system_profile["bios_id"] = bios_id
    system_profile["os_id"] = os_id
    system_profile["system_id"] = system_id
    system_profile["disk_id"] = disk_id
    system_profile["os_version"] = os_version
    system_profile["hostname"] = hostname
    system_profile["mac_list"] = mac_list
    system_profile["cpu"] = cpu
    system_profile["memory"] = memory
    token = cloudutils.getToken()

end

function downloadPackage(profile, currentVersion, packageType, update_directory)
    local package_extension = system_profile["platform"] == 'mac' and ".pkg" or ".dat"
    local downloaded
    local version
    local resource
    local partial_download_location
    local total_parts
    local file_size

    version, resource, cdn_url, partial_download_location, total_parts, file_size = cloudutils.tokenWrapper(getCloudVersion, profile, packageType, currentVersion)
    if version ~= nil and resource ~= nil then 
        log.debug("Updater: get version from cloud for package = " .. packageType)
        if compareVersion(currentVersion, version) then
            -- Push back the version to aggregator, so that it can save and track after service restart
            -- This code needs to be done after we finalize how state will be saved
            log.debug("New version available for pkg:" .. packageType .. " " .. "curr:" .. currentVersion .." new:" .. version)
            local pkg_file_path = update_directory ..  packageType .. package_extension
            downloaded = cloudutils.tokenWrapper(downloadPackageHelper, packageType, resource, update_directory, pkg_file_path, version, cdn_url, partial_download_location, total_parts, file_size)
            if downloaded then
                log.warn("Updater : New version downloaded for " .. packageType)
                log.warn("Updater : currentVesion:" .. currentVersion .. " cloudVersion:" .. version .. " location :" .. pkg_file_path)
                return true, version, pkg_file_path
            end
            log.warn("Failed to download for pkg:" .. packageType .. " new:" .. version)
        end
    end
    return false, nil, nil
end

function pathExists(path)
    if path == nil then
        return false
    end
    local ok, err, code = os.rename(path, path)
    if not ok then
        if code == 13 then
            -- Permission denied, but it exists
            return true
        end
    end
    return ok, err
end

function installPackage(profile, packageType, version, pkg_file_path)
    log.info("Installing profile :" .. profile .. " pkgType:" .. packageType .. " version:" .. version .. " pkgFilePath:" .. pkg_file_path)
    if system_profile["platform"] == 'windows' then
        os.execute("copy /Y " .. pkg_file_path .. " " .. pkg_file_path .. "_" .. version)
        if packageType == "AGENT" then
            os.execute("cmd /c start \"" .. current_path .. "\\bin\\LcaMsiLauncher.exe\" msiexec.exe /i " .. pkg_file_path .. "_" .. version .. " /quiet /lv+ " .. pkg_file_path .. "_update.log REBOOT=REALLYSUPPRESS") 
        else
            os.execute("\"" .. current_path .. "\\bin\\LcaMsiLauncher.exe\" msiexec.exe /i " .. pkg_file_path .. "_" .. version .. " /quiet /lv+ " .. pkg_file_path .. "_update.log REBOOT=REALLYSUPPRESS") 
        end         
    elseif system_profile["platform"] == 'mac' then
        os.execute("installer -pkg " .. pkg_file_path .. " -target /")
    end
    if packageType == "AGENT" then
        -- Should not reach here .. After msi is installed all services will restart and so will this thread.
        -- If we reach here -
        --  Since we already unloaded modules , we will have to ask the sensor to reload the same, or
        --  Restart Sensor service or
        --  Wait until it restarts by itself.
        log.error("Updater : Thread did not restart after installing msi. Terminating thread and returning to parent")
        return false
    end
    -- Content and AV thread does not die
    -- After update it reloads the version
    system_profile["app_version"] = cpp_getPackageVersion("agent")
    system_profile["cont_version"] = cpp_getPackageVersion("content")
    system_profile["av_version"] = cpp_getPackageVersion("av")
    return true
end


function updateThread(profile, currentVersion, packageType, update_directory, os_id, bios_id, system_id, hostname, mac_list)
    log.debug("updateThread starting :" .. packageType)

    -- AGENT-236: delayed get for agent_id
    utils.sleep(20 * 1000)

    -- block until agent_id is loaded from storage
    system_profile["agent_id"] = cpp_storageGetBlocking("general", "AGENT_UUID")

    -- setup system_profile and get token
    if system_profile["bios_id"] == nil then
        system_profile["bios_id"] = bios_id
    end

    if system_profile["os_id"] == nil then
        system_profile["os_id"] = os_id
    end

    if system_profile["system_id"] == nil then
        system_profile["system_id"] = system_id
    end

    if system_profile["hostname"] == nil then
        system_profile["hostname"] = hostname
    end

    if system_profile["mac_list"] == nil then
        system_profile["mac_list"] = mac_list
    end

    token = cloudutils.getToken()

    -- Main loop
    while true do
        log.debug("checking for update ..")
        -- Now that we only run one AGENT thread that updates both AGENT and CONTENT. But if the lcaupdater is old,
        -- it will create content thread as well.. so no-op for content thread
        if packageType == "AGENT" then
            agentVersion = cpp_getPackageVersion("agent")
            contentVersion = cpp_getPackageVersion("content")
            avVersion = cpp_getPackageVersion("av")
            if agentVersion == nil or agentVersion == '' then
                agentVersion = "0"
            end
            if contentVersion == nil  or contentVersion == '' then
                contentVersion = "0"
            end
            if avVersion == nil  or avVersion == '' then
                avVersion = "0"
            end
            -- First download the packages
            local content_downloaded, content_pkg_ver, content_pkg_file_path = downloadPackage(profile, contentVersion, "CONTENT", update_directory)
            local agent_downloaded, agent_pkg_ver, agent_pkg_file_path = downloadPackage(profile, agentVersion, "AGENT", update_directory)

            if content_downloaded and agent_downloaded then
                -- Always update the content first
                installPackage(profile, "CONTENT", content_pkg_ver, content_pkg_file_path)
                installPackage(profile, "AGENT", agent_pkg_ver, agent_pkg_file_path)
            end

            local av_downloaded, av_pkg_ver, av_pkg_file_path = downloadPackage(profile, avVersion, "ANTIVIRUS_ENGINE", update_directory)
            if av_downloaded then
                installPackage(profile, "ANTIVIRUS_ENGINE", av_pkg_ver, av_pkg_file_path)
            end
        elseif packageType == "CUSTOM" then
            local currPkgVer = getLastCustomPackageVersion()
            if currPkgVer == nil  or currPkgVer == '' then
                currPkgVer = "0"
            end
            local custom_pkg_downloaded, custom_pkg_ver, custom_pkg_file_path = downloadPackage(profile, currPkgVer, "CUSTOM", update_directory)
            if custom_pkg_downloaded then
                if installCustomPackage(custom_pkg_ver, custom_pkg_file_path, update_directory) then
                    setLastCustomPackageVersion(custom_pkg_ver)
                end
            end
        end
        utils.sleep(UPDATE_INTERVAL * 1000)
    end
end

function generateRandomString()
    local charset = {}
    -- qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
    for i = 48,  57 do table.insert(charset, string.char(i)) end
    for i = 65,  90 do table.insert(charset, string.char(i)) end
    for i = 97, 122 do table.insert(charset, string.char(i)) end

    math.randomseed(os.time())
    if length > 0 then
        return string.random(length - 1) .. charset[math.random(1, #charset)]
    else
        return "<random>"
    end
end

-- install.lua will have a global variable called update_dir. update_dir will provide
-- the path to unzipped install folder (where install.lua is located)
function executeLuaString(lua_str, update_dir)
    local cmd_str = "return function(update_dir) " .. lua_str .. " .. end";
    cmd, err_msg = loadstring(cmd_str)
    if cmd == nil then
        return "[ERROR] Couldn't interpret code, loadstring() failed: " .. err_msg
    end
    -- try to execute the code
    utils.try(function()
        result = cmd()
    end, function(e)
        if type(e) == "string" then
            return "[ERROR] Execution failed: " .. e
        else
            return "[ERROR] Execution failed"
        end
    end)

    if type(result) ~= "string" then
        return "[ERROR] Execution completed, but returned non-string"
    end
    return result
end

function installCustomPackage(custom_pkg_ver, custom_pkg_file_path, update_directory)
    local target_dir = update_directory .. generateRandomString()
    createDir(target_dir)
    local size = cpp_decompressFile(custom_pkg_file_path, target_dir)
    if size == 0 then
        log.error("Failed to decompress src:" .. custom_pkg_file_path .. " dest:" .. target_dir)
        removeFolder(target_dir)
        return false
    end

    -- we expect install.lua to be present in the target folder
    local install_lua_file_path = target_dir .. "\\install.lua"
    if not isFile(install_lua_file_path) then
        log.error("Install.lua not present in target folder:" .. install_lua_file_path)
        removeFolder(target_dir)
        return false
    end

    -- Execute install.lua
    local lua_str = readFile(install_lua_file_path)
    if lua_str == nil or lua_str == ''  then
        log.error("Empty Install.lua in target folder:" .. install_lua_file_path)
        removeFolder(target_dir)
        return false
    end

    local res = executeLuaString(lua_str, target_dir)
    if res ~= "success" then
        log.error("Failed to execute lua script. res :" .. res)
        removeFolder(target_dir)
        return false
    end

    removeFolder(target_dir)
    return true
end

-- AV update handling
function avGetLastUpdateTime()
    local updateTime = cpp_storageGet("general", "av_update_time")
    if updateTime == nil or updateTime == '' then return 0 else return tonumber(updateTime) end
end

function avSetLastUpdateTime()
    cpp_storageSet("general", "av_update_time", tostring(os.time()))
end

function avGetServerUpdateDate()
    local serverUpdateDate = cpp_storageGet("general", "av_server_update_date")
    if serverUpdateDate == nil then
        return ''
    end
    return serverUpdateDate
end

function avSetServerUpdateDate(serverUpdateDate)
    cpp_storageSet("general", "av_server_update_date", serverUpdateDate)
end

function avGetCurrentDefsId()
    local currentDefsId = cpp_storageGet("general", "av_current_defs_id")
    if currentDefsId == nil then
        return ''
    end
    return currentDefsId
end

function avSetCurrentDefsId(currentDefsId)
    cpp_storageSet("general", "av_current_defs_id", currentDefsId)
end

function avDownloadFile(defsBaseUrl, fileId, path)
    local request_data
    local eurl = download_url

    local cloud_url = defsBaseUrl ..  fileId

    log.debug("Downloading from url:" .. cloud_url .. " to path:" .. path .. " hash:" .. fileId)

    request_data = {
        url = cloud_url,
        method = "GET",
        downloadToFile = path,
        http_timeout =  AV_HTTP_TIMEOUT,
        retry_delay = AV_HTTP_RETRY_DELAY,
        max_retry_attempts = AV_HTTP_RETRIES,
        headers = {}
    }
    cloudutils.tokenWrapper(cloudutils.sendWithToken, request_data)
    local filesize = cpp_getFileSize(path)
    if filesize == nil or filesize == 0 then
        log.error("Failed to download from url:" .. cloud_url)
        return false
    end

    local downloaded_hash = cpp_hashFile(path, "md5")
    if not strEqual(local_hash, hash, true) then
        log.error("Downloaded file [" .. path .. "] hash mismatch.")
        return false
    end
    return true
end

function avDownloadFileToBuffer(defsBaseUrl, fileId)
    local request_data
    local cloud_url = defsBaseUrl .. fileId

    log.debug("Downloading to buffer from url:" .. cloud_url)

    local request_data = {
        url = cloud_url,
        method = "GET",
        headers = {},
        http_timeout = AV_HTTP_TIMEOUT,
        retry_delay = AV_HTTP_RETRY_DELAY,
        max_retry_attempts = AV_HTTP_RETRIES
    }

    -- send request
    return cloudutils.tokenWrapper(cloudutils.sendWithToken, request_data)
end

function readFile(filePath)
    if filePath == nil then return "" end
    local file = io.open(filePath, "r")
    if file == nil then
        log.info("Failed to open :" .. filePath)
        return nil
    end

    local buff = file:read("*all")
    file:close()
    return buff
end

-- wrap string in double quotes
local dqwrap = function(str)
  return '"'..str..'"'
end

function regWriteValue(key, name, vtype, value)
    local cmd
    if name == "(Default)" or name == nil then
        cmd = ("reg.exe add %s /ve /t %s /d %s /f"):format(dqwrap(key), vtype, value)
    else
        cmd = ("reg.exe add %s /v %s /t %s /d %s /f"):format(dqwrap(key),dqwrap(name), vtype, value)
    end
    os.execute(cmd)
    return true
end

function isFilePresentLocally(path, hash, targetDir)
    -- check if the file is present in target dir_path
    if targetDir == nil then
        return false
    end
    local local_path = targetDir .. path
    local_path = local_path:gsub('/', '\\')
    local local_hash = cpp_hashFile(local_path, "md5")
    return strEqual(local_hash, hash, true)
end

function isFilePresentInList(path, hash, list)
    if list  == nil or path == nil or hash == nil then
        return false
    end

    for idx,dict in ipairs(list) do
        if dict ~= nil and type(dict) == "table" and strEqual(dict["path"], path, true) and strEqual(dict["hash"], hash, true) then
            return true
        end
    end
    return false
end

function printList(list)
    for idx,dict in ipairs(list) do
        log.info("path :" .. dict["path"] .. " hash:" .. dict["hash"])
    end
end

function diffAVUpdateList(serverJson, localJson, tmpDir, targetDir)
    if serverJson == nil then
        log.debug("Empty hash.json from server")
        return nil,nil
    end

    if localJson ~= nil and localJson["UPDATE_TIME"] ~= nil and serverJson["UPDATE_TIME"] == localJson["UPDATE_TIME"] then
        log.debug("hash.json not changed. No new updates available")
        return nil,nil
    end

    if serverJson['DATA'] == nil then
        log.warn("Invalid hash.json received from server")
        return nil,nil
    end

    local localDict
    if localJson ~= nil then
        localDict = localJson['DATA']
    end

    -- Generate a list of new files to be downloaded
    list_diff_add = {}
    list_not_changed = {}

    local existingCount = 0
    local downloadCount = 0
    for path,hash in pairs(serverJson['DATA']) do
        if path ~= nil and hash ~= nil then
            local dict = {}
            dict["path"] = path
            dict["hash"] = hash
            if not isFilePresentLocally(path, hash, targetDir) then
                table.insert(list_diff_add, dict)
                log.debug("Download new file :" .. path .. " hash:" .. hash)
                downloadCount = downloadCount + 1
            else
                table.insert(list_not_changed, dict)
                existingCount = existingCount + 1
            end
        else
            log.warn("Unexpected. path or hash not set")
        end
    end

    -- Generate a list of files to be deleted from client
    list_diff_del = {}
    local delFilesCount = 0
    if localDict ~= nil then
        for path,hash in pairs(localDict) do
            if not isFilePresentInList(path, hash, list_not_changed) then
                log.debug("Delete file :" .. path .. " hash:" .. hash)
                local dict = {}
                dict["path"] = path
                dict["hash"] = hash
                table.insert(list_diff_del, dict)
                delFilesCount = delFilesCount + 1
            end
        end
    end

    log.debug("New download cnt:" .. downloadCount .. " Not changed cnt:" ..existingCount.. " delete cnt:" .. delFilesCount)
    return list_diff_add,list_diff_del
end

getPath=function(str)
    return str:match("(.*[/\\])")
end

strEqual=function(s1, s2, ignoreCase)
    if s1 == nil and s2 == nil then return true end
    if s1 == nil or s2 == nil then return false end

    if ignoreCase then
        s1 = string.lower(s1)
        s2 = string.lower(s2)
    end
    return s1 == s2
end

function downloadAVUpdate(defsBaseUrl, listUpdate, cachePath)
    if listUpdate == nil then
        -- nothing to download
        return true
    end
    local count = 1
    for idx, dict in ipairs(listUpdate) do
        if dict ~= nil and type(dict) == "table" then
           local path = cachePath .. dict["path"]
            local folder_path = getPath(path)
            if not pathExists(folder_path) then
                createDir(folder_path)
            end
            if not avDownloadFile(defsBaseUrl, dict["hash"], path) then
                log.warn("Failed to download def :".. dict["path"])
                return false
            end
            count = count + 1
        else
            log.warn("Unexpected! entry is empty for idx :" .. idx)
        end
    end
    log.debug("Total files downloaded :" .. count)
    return true
end

function verifyAVDownloads(serverHashJson, avDefTargetFolder, avDownloadTmpFolder)
    if serverHashJson == nil then
        log.error("Unpected! serverHashJson is nil")
        return false
    end

    local dict = {}
    if serverHashJson ~= nil then
        dict = serverHashJson['DATA']
    end

    local res = true
    for path,hash in pairs(dict) do
        if path ~= nil and hash ~= nil then
            if isFilePresentLocally(path, hash, avDownloadTmpFolder) then
                log.debug("File path:" .. path .. " hash:" .. hash.. " present in downloaded tmp folder " .. avDownloadTmpFolder)
            elseif isFilePresentLocally(path, hash, avDefTargetFolder) then
                log.debug("File path:" .. path .. " hash:" .. hash.. " present in defs folder " .. avDefTargetFolder)
            else
                log.error("Unexpected! File path:" .. path .. " hash:" .. hash.. " locally found")
                res = false
            end
        else
            log.error("Invalid entry in .cache file")
            res = false
        end
    end
    if res ~= true then
        log.error("Failed to verify AV downloads!")
    end
    return res
end

function delFilesFromTarget(list, targetDir)
    if list == nil then
        log.debug("list is nil")
    end

    if targetDir == nil then 
        log.debug("targetDir is nil")
    end

    if list == nil or targetDir == nil then
        log.debug("No files to delete")
        return
    end

    for idx,dict in ipairs(list) do
        local targetPath = targetDir .. dict["path"]
        local retry_count = 10
        local ok = false
        while not ok and retry_count > 0 do
            ok, err = os.remove(targetPath)
            if not ok then
                log.error("Failed to delete " .. targetPath .. " err:" .. err)
                utils.sleep(500)
                retry_count = retry_count - 1
            end
        end
    end
end

function moveFilesToTarget(list, srcDir, targetDir)
    if list == nil or srcDir == nil or targetDir == nil then
        log.debug("No files to move")
        return false
    end

    for idx,dict in ipairs(list) do
        local srcPath = srcDir .. dict["path"]
        local targetPath = targetDir .. dict["path"]
        local targetFolderPath = getPath(targetPath)
        if not pathExists(targetFolderPath) then
            createDir(targetFolderPath)
        end

        -- First delet the targetPath
        os.remove(targetPath)

        ok, errmsg = os.rename(srcPath, targetPath)
        if not ok then
            log.error("Failed to rename :" .. srcPath .. "->" .. targetPath .. ". Err:" .. errmsg)
        end
    end
    return true
end

function setAVWorkDone(val)
    local res = regWriteValue(AV_REG_KEY, AV_WORK_DONE_NAME, "REG_DWORD", val)
    if res ~= true then
        log.error("Failed to set AV WorkDone entry")
        return false
    end
end

function startAVEngine()
    setAVWorkDone("1")
    local res = regWriteValue(AV_REG_KEY, AV_UNLOAD_NAME, "REG_DWORD", "0")
    if res ~= true then
        log.error("Failed to start AV engine")
        return false
    end
    log.info("Started AV engine")
    return true
end

function stopAVEngine()
    local res = regWriteValue(AV_REG_KEY, AV_UNLOAD_NAME, "REG_DWORD", "1")
    if res ~= true then
        log.error("Failed to stop AV engine")
        return false
    end
    setAVWorkDone("1")
    utils.sleep(10000)
    log.info("Stopped AV engine")
    return true
end

function saveHashToFile(content, file_path)
    local file = io.open(file_path, "w")
    if file == nil then
        log.error("Failed to open file for writing :" .. file_path)
        return false
    end
    file:write(content)
    file:close()
    return true
end

function removeFolder(folder_path)
    log.debug("removeFolder :" .. folder_path)
    os.execute('rd /s/q "'..folder_path..'"')
end

function createDir(folder_path)
    os.execute("mkdir \"" .. folder_path .. "\"")
end

function avGetLatestAvDefsMetadata()
    local arch
    if system_profile["arch"] == 64 or system_profile["arch"] == "x64" then
        arch = "x64"
    else
        arch = "x86"
    end

    local data = {
        ["agentUuid"] = system_profile["agent_id"],
        ["version"] = system_profile["app_version"],
        ["platform"] = system_profile["platform"],
        ["architecture"] = arch,
        ["defsId"] = avGetCurrentDefsId(),
        ["serverUpdateDate"] = avGetServerUpdateDate(),
        ["product"] = "Antiy",
    }
    local data_json = utils.json_encode(data)

    local request_data
    request_data = {
        url = AV_UPDATE_URL .. 'meta',
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = data_json:len()
        },
        data = data_json,
        http_timeout =  AV_HTTP_TIMEOUT,
        retry_delay = AV_HTTP_RETRY_DELAY,
        max_retry_attempts = AV_HTTP_RETRIES
    }

    local response = cloudutils.tokenWrapper(cloudutils.sendWithToken, request_data)
    if response == nil or response == '' then
        log.warn("Failed to get meta. empty response received")
        return nil
    end

    local metaJson = utils.json_decode(response)
    if metaJson ~= nil and type(metaJson) == "table" and metaJson["defsId"] ~= nil then
        log.debug("Latest defsId:" .. metaJson["defsId"])
        return metaJson
    else
        log.warn("Invalid AV meta returned. response:" .. response)
    end
    return nil
end

function verifyAVDefs(targetDir)
    local localJson
    local localHashFilePath = avDefTargetFolder .. AV_LOCAL_CACHE_FILE_NAME
    local localHashJsonStr = readFile(localHashFilePath)
    if localHashJsonStr ~= nil and localHashJsonStr ~= "" then
        localJson = utils.json_decode(localHashJsonStr)
    else
        log.error("Unexpected! local hash.json not present : " .. localHashFilePath)
        return false
    end

    local localDict
    if localJson ~= nil then
        localDict = localJson['DATA']
    else
        log.error("Invalid .cache file")
        return false
    end

    local res = true
    for path,hash in pairs(localDict) do
        if path ~= nil and hash ~= nil then
            if not isFilePresentLocally(path, hash, targetDir) then
                log.error("File path:" .. path .. " hash:" .. hash.. " locally not present")
                res = false
            end
        else
            log.error("Invalid entry in .cache file")
            res = false
        end
    end
    if res ~= true then
        log.info("Failed to verify AV downloads!")
    end
    return res
end

function updateAVDefs()
    log.debug("Download AVDefs ...")
    token = cloudutils.getToken()
    local avMetaJson = avGetLatestAvDefsMetadata()
    if avMetaJson == nil then
        log.error("Invalid avDefs metadata received")
        return false
    end

    if avMetaJson["avUpdateUrl"] == nil or avMetaJson["hashJsonId"] == nil or avMetaJson["serverUpdateDate"] == nil or avMetaJson["defsId"] == nil then
        log.error("Invalid avDefs metadata received")
        return false
    end

    local defsBaseUrl = avMetaJson["avUpdateUrl"]
    local hashJsonId = avMetaJson["hashJsonId"]
    local serverUpdateDate = avMetaJson["serverUpdateDate"]
    local defsId = avMetaJson["defsId"]

    log.debug("DefsId:" .. defsId .. ",baseUrl:" .. defsBaseUrl .. ",hashJsonId:" .. hashJsonId .. ",updateTime:" .. serverUpdateDate)
    -- Delete tmp folder if present
    removeFolder(avDownloadTmpFolder)

    -- First download hash.json file
    local serverHashJsonStr = avDownloadFileToBuffer(defsBaseUrl, hashJsonId)
    if serverHashJsonStr == nil or serverHashJsonStr == '' then
        log.warn("Failed to download hash.json")
        return false
    end

    log.debug("hash.json downloaded")

    -- decode response and check for errors
    local serverHashJson = utils.json_decode(serverHashJsonStr)
    if type(serverHashJson) ~= "table" then
        log.error("Malformed response from cloud for hash.json.. type : ".. type(json_response))
        return false
    end

    -- Read the existing hash.json from the AV Avl folder
    local localHashFilePath = avDefTargetFolder .. AV_LOCAL_CACHE_FILE_NAME
    local localHashJsonStr = readFile(localHashFilePath)
    local localHashJson = {
        ["TimeStamp"] = nil,
        ["Data"] = {}
    }
    if localHashJsonStr ~= nil and localHashJsonStr ~= "" then
        localHashJson = utils.json_decode(localHashJsonStr)
    else
        log.debug("local hash.json not present : " .. localHashFilePath)
    end

    local listAdd,listDel = diffAVUpdateList(serverHashJson, localHashJson, avDownloadTmpFolder, avDefTargetFolder)
    if listAdd == nil and listDel == nil then
        -- nothing to update
        setAVWorkDone("1")
        log.debug("No new updates available.")
        return true
    end

    if not downloadAVUpdate(defsBaseUrl, listAdd, avDownloadTmpFolder) then
        log.warn("Failed to download one or more def files")
        return false
    end

    if not verifyAVDownloads(serverHashJson, avDefTargetFolder, avDownloadTmpFolder) then
        log.error("Unexpected! Downloaded corrupt definitions!")
        return false
    else
        log.debug("Downloaded Defs are valid")
    end

    -- Stop AV engine
    if not stopAVEngine() then
        log.warn("Failed to stop AV Engine")
        return false
    end

    delFilesFromTarget(listDel, avDefTargetFolder)

    local success = true
    if not moveFilesToTarget(listAdd, avDownloadTmpFolder, avDefTargetFolder) then
        log.warn("Failed to move AV Defs from tmp location :"  .. avDownloadTmpFolder .. " to target:" .. avDefTargetFolder)
        success = false
    end

    -- Save hash.json file to localHashFilePath for .cache
    if not saveHashToFile(serverHashJsonStr, localHashFilePath) then
        log.warn("Failed to save hash.json to :"  .. localHashFilePath)
        success = false
    end

    if verifyAVDefs(avDefTargetFolder) ~= true then
        log.error("Unexpected! failed. Downloaded corrupt definitions!")
        success = false
    end

    if not startAVEngine() then
        log.warn("Failed to start AV Engine")
        success = false
    end

    if not success then
        log.error("one or more operations failed. Try again")
        return false
    end

    avSetLastUpdateTime()
    avSetCurrentDefsId(defsId)
    avSetServerUpdateDate(serverUpdateDate)

    removeFolder(avDownloadTmpFolder)
    log.debug("Successly updated AV Defs")
    return true
end

function isAVInstalled()
    return pathExists(avDefTargetFolder)
end

function avContentUpdateThread(profile)
    log.debug("avContentUpdateThread: starting ...")

    AV_UPDATE_URL = AV_UPDATE_URL .. "/aapi/v1/avDefs/"
    if cpp_getAVInstallRoot == nil then
        log.warn("Unexpected! cpp_getAVInstallRoot() function not available")
        return
    end

    avInstallRoot = cpp_getAVInstallRoot()
    if not pathExists(avInstallRoot) then
        createDir(avInstallRoot)
    end
    avDefTargetFolder = avInstallRoot .. "\\bin\\avl\\"

    avDownloadTmpFolder = data_path .. AV_SIG_DIR_NAME
    if not pathExists(avDownloadTmpFolder) then
        createDir(avDownloadTmpFolder)
    end
    avDownloadTmpFolder = avDownloadTmpFolder .. "\\"

    log.debug("av Install Root :" .. avInstallRoot .. " Def Target :" .. avDefTargetFolder .. " Tmp Download :" .. avDownloadTmpFolder)

    -- block until agent_id is loaded from storage
    system_profile["agent_id"] = cpp_storageGetBlocking("general", "AGENT_UUID")

    utils.sleep(30000)

    while (true) do
        -- Check last AV update time.. we check every 12 hours
        local lastAVCheckTime = avGetLastUpdateTime()
        local currTime = os.time()
        local sleepMs = 10*SEC_MS
        local avInstalled = isAVInstalled()
        if avInstalled and currTime - lastAVCheckTime >= 1*HOURS_IN_SECS then
            updateAVDefs()
        end
        utils.sleep(sleepMs)
    end
end