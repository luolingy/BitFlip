// MSVC 名字反修饰的端到端样本（M8 遗留项）。
//
// 刻意不 include 任何头文件：clang-cl 在没有 vcvars 环境时找不到 MSVC 的标准库头，
// 而这里验证的是"修饰名能不能被读懂"，不需要任何运行时。
//
// 用 extern "C" 的入口是为了能 /entry: 链接；类成员函数则保留 MSVC 的修饰名
// （`?bar@Widget@@QEAAHH@Z` 这类），它们就是被测对象。

class Widget {
public:
    int bar(int x) { return x + 1; }
    void method(const char *text) { (void)text; }
};

static Widget g_widget;

extern "C" int bf_cxx_entry(int n) { return g_widget.bar(n); }