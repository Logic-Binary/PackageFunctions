#include "MyFileInfo.h"

// ��ȡ��ǰ����·��
DWORD GetMyProcessDir(LPWSTR& lpDirPath)
{
    return GetCurrentDirectory(MAX_PATH, lpDirPath);
}
// ���õ�ǰ����·��
BOOL SetMyProcessDir(LPWSTR lpNewDir)
{
    return SetCurrentDirectory(lpNewDir);
}
// ��ȡ��ǰ�ļ�·��
DWORD GetMyProcessImagePath(LPWSTR& lpDirPath)
{
    return GetModuleFileName(NULL, lpDirPath, MAX_PATH);
}
// ��ȡģ���·��
DWORD GetProcessImagePath(LPWSTR lpName, LPWSTR& lpPath)
{
    return GetModuleFileName(GetModuleHandle(lpName), lpPath, MAX_PATH);
}

BOOL SetFileIsOnlyRead(LPWSTR lpPath) {
    // 1. ��ȡԭ�����ļ�����
    DWORD dwFileAttributes = GetFileAttributes(lpPath);
    // 2. ��ֻ�����Ը��ӵ�ԭ�����ļ�������
    dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
    // 3. �����ļ�����
    return SetFileAttributes(lpPath, dwFileAttributes);
}

BOOL SetFileIsHidden(LPWSTR lpPath) {
    // 1. ��ȡԭ�����ļ�����
    DWORD dwFileAttributes = GetFileAttributes(lpPath);
    // 2. ���������Ը��ӵ�ԭ�����ļ�������
    dwFileAttributes |= FILE_ATTRIBUTE_HIDDEN;
    // 3. �����ļ�����
    return SetFileAttributes(lpPath, dwFileAttributes);
}

BOOL GetFileAttribute(LPWSTR lpPath, FILE_INFO& stcFileInfo) {
    // 1. �ļ�·��
    wcscpy_s(stcFileInfo.szFilePath, lpPath);
    // 2. ��ȡʱ����Ϣ
    WIN32_FILE_ATTRIBUTE_DATA wfad;
    GetFileAttributesEx(lpPath, GetFileExInfoStandard, &wfad);
    // 2.1 ��ȡ����ʱ��
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&wfad.ftCreationTime, &ftLocal);   // ����Ϊϵͳ����ʱ����ʱ��
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // ת��ΪSYSTEMTIME��ʽ
    // 2.2 ��ȡ������ʱ��
    FileTimeToLocalFileTime(&wfad.ftLastAccessTime, &ftLocal); // ����Ϊϵͳ����ʱ����ʱ��
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // ת��ΪSYSTEMTIME��ʽ
    // 2.3 ��ȡ����޸�ʱ��
    FileTimeToLocalFileTime(&wfad.ftLastWriteTime, &ftLocal);  // ����Ϊϵͳ����ʱ����ʱ��
    FileTimeToSystemTime(&ftLocal, &stcFileInfo.stcCreatTime); // ת��ΪSYSTEMTIME��ʽ
    // 3. ��ȡ�ļ���С
    stcFileInfo.qwFileSize = wfad.nFileSizeHigh;
    stcFileInfo.qwFileSize <<= sizeof(DWORD) * 8;
    stcFileInfo.qwFileSize += wfad.nFileSizeLow;
    // 4. �ļ�����
    stcFileInfo.dwAttribute = wfad.dwFileAttributes;
    if (stcFileInfo.dwAttribute & FILE_ATTRIBUTE_ARCHIVE)
        wcscpy_s(stcFileInfo.szAttributeDescription, L"<ARCHIVE> ");
    // �Ƚ���������
    return TRUE;
}

BOOL GetFileList(LPWSTR lpName, list<FILE_INFO>& lstFileInfo) {
    // 1. ���������Ŀ¼���ļ���·�����ַ�����ʹ��ͨ�����*��
    WCHAR szFilePath[MAX_PATH];
    StringCbCopy(szFilePath, MAX_PATH, lpName);
    StringCbCat(szFilePath, MAX_PATH, L"\\*");
    // 2. ��ȡ��һ���ļ�/Ŀ¼������ò��Ҿ��
    WIN32_FIND_DATA FindFileData;
    HANDLE hListFile = FindFirstFile(szFilePath, &FindFileData);
    if (INVALID_HANDLE_VALUE == hListFile)   return FALSE;
    // 3. ��ʼѭ��������ȡ�ļ���
    do {
        FILE_INFO stcInfo = { 0 };
        // 3.1 �ж��Ƿ��Ǳ���Ŀ¼���ϼ�Ŀ¼�����ƣ��ǵĻ����������ѭ��
        if (!lstrcmp(FindFileData.cFileName, L".")
            || !lstrcmp(FindFileData.cFileName, L"..")) {
            continue;
        }
        // 3.2 ����ȡ�����ļ��������ڽṹ����
        StringCbCopy(stcInfo.szFilePath, MAX_PATH, FindFileData.cFileName);
        // 3.3 ��ȡ����·����
        WCHAR szFullPath[MAX_PATH];
        StringCbPrintf(szFullPath, MAX_PATH, L"%s\\%s", lpName, FindFileData.cFileName);
        // 3.4 �������Ŀ¼�����ȡ��ϸ��Ϣ
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            stcInfo.bIsFolder = TRUE;
        else
            GetFileAttribute(szFullPath, stcInfo);
        // 3.5 ����ȡ�����ļ���Ϣѹ�뵽������
        lstFileInfo.push_back(stcInfo);
    } while (FindNextFile(hListFile, &FindFileData));

    return TRUE;
}
