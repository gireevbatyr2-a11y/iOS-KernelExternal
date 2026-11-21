#import "RootViewController.h"
#import "Engine.h"
#include <stdlib.h>

static void logTo(NSMutableString *log, UITextView *view, NSString *fmt, ...) NS_FORMAT_FUNCTION(3, 4);
static void logTo(NSMutableString *log, UITextView *view, NSString *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    [log appendString:line];
    [log appendString:@"\n"];
    view.text = log;
    [view scrollRangeToVisible:NSMakeRange(log.length, 0)];
}

@interface RootViewController ()
@property (nonatomic, strong) NSMutableString *log;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UITextField *addrField;
@property (nonatomic, strong) UITextField *valueField;
@property (nonatomic, strong) UIButton *readButton;
@property (nonatomic, strong) UIButton *writeButton;
@property (nonatomic, strong) UIButton *zeroButton;
@property (nonatomic, copy) NSString *backendStatus;
@property (nonatomic, assign) BOOL backendReady;
@property (nonatomic, strong) NSArray *processes;
@end

@implementation RootViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"External";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.log = [NSMutableString string];
    self.processes = @[];

    [self buildUI];
    [self startKernel];
}

- (void)buildUI
{
    CGRect f = self.view.bounds;
    f.origin.y = 0;
    self.table = [[UITableView alloc] initWithFrame:CGRectMake(0, 0, f.size.width, f.size.height * 0.4) style:UITableViewStylePlain];
    self.table.delegate = self;
    self.table.dataSource = self;
    [self.view addSubview:self.table];

    self.addrField = [self makeField:@"0xaddress"];
    self.valueField = [self makeField:@"hex value"];

    CGFloat y = CGRectGetMaxY(self.table.frame) + 8;
    self.addrField.frame = CGRectMake(12, y, f.size.width - 24, 36);
    self.valueField.frame = CGRectMake(12, y + 42, f.size.width - 24, 36);
    [self.view addSubview:self.addrField];
    [self.view addSubview:self.valueField];

    y += 88;
    self.readButton = [self makeButton:@"Read" selector:@selector(doRead)];
    self.writeButton = [self makeButton:@"Write" selector:@selector(doWrite)];
    self.zeroButton = [self makeButton:@"Zero extmods" selector:@selector(doZero)];

    self.readButton.frame = CGRectMake(12, y, (f.size.width - 36) / 3, 36);
    self.writeButton.frame = CGRectMake(12 + (f.size.width - 36) / 3 + 6, y, (f.size.width - 36) / 3, 36);
    self.zeroButton.frame = CGRectMake(12 + 2 * ((f.size.width - 36) / 3 + 6), y, (f.size.width - 36) / 3, 36);
    [self.view addSubview:self.readButton];
    [self.view addSubview:self.writeButton];
    [self.view addSubview:self.zeroButton];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(0, y + 44, f.size.width, f.size.height - (y + 44))];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [self.view addSubview:self.logView];

    UIBarButtonItem *refresh = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refreshProcesses)];
    self.navigationItem.rightBarButtonItem = refresh;
}

- (UITextField *)makeField:(NSString *)placeholder
{
    UITextField *field = [[UITextField alloc] init];
    field.placeholder = placeholder;
    field.delegate = self;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.borderStyle = UITextBorderStyleRoundedRect;
    field.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    return field;
}

- (UIButton *)makeButton:(NSString *)title selector:(SEL)sel
{
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:title forState:UIControlStateNormal];
    [button addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)startKernel
{
    Engine *engine = [Engine shared];
    NSString *err = [engine startKernel];
    if (err) {
        self.backendReady = NO;
        self.backendStatus = err;
    } else {
        self.backendReady = YES;
        self.backendStatus = [NSString stringWithFormat:@"kernel backend: %@", engine.backendName];
    }
    self.logView.text = self.backendStatus;
}

- (void)refreshProcesses
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        KEProcessInfo *list = NULL;
        size_t count = 0;
        keProcessList(&list, &count);
        NSMutableArray *rows = [NSMutableArray array];
        for (size_t i = 0; i < count; i++) {
            NSString *name = [NSString stringWithUTF8String:list[i].name];
            if (name.length == 0) continue;
            [rows addObject:[NSString stringWithFormat:@"%d\t%@", list[i].pid, name]];
        }
        if (list) free(list);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.processes = rows;
            [self.table reloadData];
            logTo(self.log, self.logView, @"process list: %zu entries", rows.count);
        });
    });
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.processes.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *reuse = @"cell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:reuse];
    cell.textLabel.text = [self.processes[indexPath.row] componentsSeparatedByString:@"\t"][1];
    cell.detailTextLabel.text = [self.processes[indexPath.row] componentsSeparatedByString:@"\t"][0];
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSString *row = self.processes[indexPath.row];
    pid_t pid = [row componentsSeparatedByString:@"\t"][0].intValue;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *err = [[Engine shared] attach:pid];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (err) {
                logTo(self.log, self.logView, @"attach %d: %@", pid, err);
            } else {
                logTo(self.log, self.logView, @"attached to %d (extmod zeroed)", pid);
                [self updateButtons];
            }
        });
    });
}

- (void)updateButtons
{
    BOOL attached = [[Engine shared] attached];
    self.readButton.enabled = attached;
    self.writeButton.enabled = attached;
    self.zeroButton.enabled = attached;
}

- (uint64_t)parsedAddr
{
    NSString *text = self.addrField.text ?: @"";
    if ([text hasPrefix:@"0x"] || [text hasPrefix:@"0X"]) text = [text substringFromIndex:2];
    return strtoull(text.UTF8String, NULL, 16);
}

- (void)doRead
{
    uint64_t addr = [self parsedAddr];
    NSString *hex = [[Engine shared] readHex:addr size:8];
    logTo(self.log, self.logView, @"read 0x%llx -> %@", addr, hex ?: @"failed");
    self.valueField.text = hex;
}

- (void)doWrite
{
    uint64_t addr = [self parsedAddr];
    NSString *err = [[Engine shared] writeHex:addr hex:self.valueField.text ?: @""];
    if (err) {
        logTo(self.log, self.logView, @"write 0x%llx: %@", addr, err);
    } else {
        logTo(self.log, self.logView, @"wrote 0x%llx", addr);
    }
}

- (void)doZero
{
    [[Engine shared] zeroExtmods];
    logTo(self.log, self.logView, @"extmod counters zeroed (target + self)");
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField
{
    [textField resignFirstResponder];
    return YES;
}

@end
