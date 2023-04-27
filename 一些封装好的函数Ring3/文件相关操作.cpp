#include "MyFileInfo.h"

// 获取当前工作路径
DWORD GetMyProcessDir(LPWSTR& lpDirPath)
{
    return GetCurrentDirectory(MAX_PATH, lpDirPath);
}
// 设置当前工作路径
BOOL SetMyProcessDir(LPWSTR lpNewDir)
{
    return SetCurrentDirectory(lpNewDir);
}
// 获取当前文件路径
DWORD GetMyProcessImagePath(LPWSTR& lpDirPath)
{
    return GetModuleFileName(NULL, lpDirPath, MAX_PATH);
}
// 获取模块的路径
DWORD GetProcessImagePath(LPWSTR lpName, LPWSTR& lpPath)
{
    return GetModuleFileName(GetModuleHandle(lpName), lpPath, MAX_PATH);
}

BOOL SetFileIsOnlyRead(LPWSTR lpPath) {
    // 1. 获取原来的文件属性
    DWORD dwFileAttributes = GetFileAttributes(lpPath);
    // 2. 将只读属性附加到原来的文件属性上
    dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
    // 3. 设置文件属性
    return SetFileAttributes(lpPath, dwFileAttributes);
}

BOOL SetFileIsHidden(LPWSTR lpPath) {
    // 1. 获取原来的文件属性
    DWORD dwFileAttributes = GetFileAttributes(lpPath);
    // 2. 将隐藏属性附加到原来的文件属性上
    dwFileAttributes |= FILE_ATTRIBUTE_HIDDEN;
    // 3. 设置文件属性
    return SetFileAttributes(lpPath, dwFileAttributes);
}

BOOL GetFileAttribute(LPWSTR lpPath, FILE_INFO& stcFileInfo) {
    // 1. 文件路径
    wcscpy_s(stcFileInfo.szFilePath, lpPath);
    // 2. 获取时间信息
    WIN32_FILE_ATTRIBUTE_DATA wfad;
    GetFileAttributesEx(lpPath, GetFileExInfoStandard, &wfad);
    // 2.1 获取创建时间
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&wfad.ftCreationTime, &ftLocal);   // 调整为系统所在时区的时间
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // 转换为SYSTEMTIME格式
    // 2.2 获取最后访问时间
    FileTimeToLocalFileTime(&wfad.ftLastAccessTime, &ftLocal); // 调整为系统所在时区的时间
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // 转换为SYSTEMTIME格式
    // 2.3 获取最后修改时间
    FileTimeToLocalFileTime(&wfad.ftLastWriteTime, &ftLocal);  // 调整为系统所在时区的时间
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // 转换为SYSTEMTIME格式
    // 3. 获取文件大小
    stcFileInfo.qwFileSize = wfad.nFileSizeHigh;
    stcFileInfo.qwFileSize <<= sizeof(DWORD) * 8;
    stcFileInfo.qwFileSize += wfad.nFileSizeLow;
    // 4. 文件属性
    stcFileInfo.dwAttribute = wfad.dwFileAttributes;
    if (stcFileInfo.dwAttribute & FILE_ATTRIBUTE_ARCHIVE)
        wcscpy_s(stcFileInfo.szAttributeDescription, L"<ARCHIVE> ");
    // 比较其它类型
    return TRUE;
}

BOOL GetFileList(LPWSTR lpName, list<FILE_INFO>& lstFileInfo) {
    // 1. 构造代表子目录和文件夹路径的字符串，使用通配符“*”
    WCHAR szFilePath[MAX_PATH];
    StringCbCopy(szFilePath, MAX_PATH, lpName);
    StringCbCat(szFilePath, MAX_PATH, L"\\*");
    // 2. 获取第一个文件/目录，并获得查找句柄
    WIN32_FIND_DATA FindFileData;
    HANDLE hListFile = FindFirstFile(szFilePath, &FindFileData);
    if (INVALID_HANDLE_VALUE == hListFile)   return FALSE;
    // 3. 开始循环遍历获取文件名
    do {
        FILE_INFO stcInfo = { 0 };
        // 3.1 判断是否是本级目录或上级目录的名称，是的话则结束本次循环
        if (!lstrcmp(FindFileData.cFileName, L".")
            || !lstrcmp(FindFileData.cFileName, L"..")) {
            continue;
        }
        // 3.2 将获取到的文件名保存在结构体中
        StringCbCopy(stcInfo.szFilePath, MAX_PATH, FindFileData.cFileName);
        // 3.3 获取完整路径名
        WCHAR szFullPath[MAX_PATH];
        StringCbPrintf(szFullPath, MAX_PATH, L"%s\\%s", lpName, FindFileData.cFileName);
        // 3.4 如果不是目录，则获取详细信息
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            stcInfo.bIsFolder = TRUE;
        else
            GetFileAttribute(szFullPath, stcInfo);
        // 3.5 将获取到的文件信息压入到链表中
        lstFileInfo.push_back(stcInfo);
    } while (FindNextFile(hListFile, &FindFileData));

    return TRUE;
}
