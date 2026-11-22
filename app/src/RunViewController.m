#import "RunViewController.h"
#import "Engine.h"

// edit these to point Run at your target process
static NSString * const kDefaultTargetProcess = @"UnityFramework";

@interface RunViewController () <UITableViewDelegate, UITableViewDataSource>
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *runButton;
@property (nonatomic, strong) UITableView *processTable;
@property (nonatomic, strong) UILabel *logLabel;
@property (nonatomic, strong) NSMutableArray<NSString *> *processes;
@end

@implementation RunViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Run";
    self.processes = [NSMutableArray array];

    self.view.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.06 alpha:1.0];

    self.titleLabel = [[UILabel alloc] init];
    self.titleLabel.text = @"Kernel External";
    self.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    self.titleLabel.textColor = [UIColor whiteColor];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:self.titleLabel];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    self.statusLabel.textColor = [UIColor colorWithWhite:0.72 alpha:1.0];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 0;
    [self.view addSubview:self.statusLabel];

    self.runButton = [UIButton buttonWithType:UIButtonTypeCustom];
    self.runButton.layer.cornerRadius = 80;
    self.runButton.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.30 alpha:1.0];
    [self.runButton setTitle:@"Run" forState:UIControlStateNormal];
    [self.runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.runButton.titleLabel.font = [UIFont systemFontOfSize:34 weight:UIFontWeightHeavy];
    self.runButton.layer.shadowColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.30 alpha:1.0].CGColor;
    self.runButton.layer.shadowRadius = 24;
    self.runButton.layer.shadowOpacity = 0.55;
    self.runButton.layer.shadowOffset = CGSizeZero;
    [self.runButton addTarget:self action:@selector(runTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.runButton];

    self.processTable = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    self.processTable.delegate = self;
    self.processTable.dataSource = self;
    self.processTable.backgroundColor = [UIColor clearColor];
    self.processTable.separatorColor = [UIColor colorWithWhite:0.18 alpha:1.0];
    [self.view addSubview:self.processTable];

    self.logLabel = [[UILabel alloc] init];
    self.logLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logLabel.textColor = [UIColor colorWithWhite:0.5 alpha:1.0];
    self.logLabel.numberOfLines = 2;
    [self.view addSubview:self.logLabel];

    UIBarButtonItem *refresh = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refreshProcesses)];
    [self.navigationItem setRightBarButtonItem:refresh];

    // Kernel/exploit init is NEVER automatic at app launch: the landa race must
    // only run when the user explicitly presses Run (one-shot per boot guard).
}

- (void)viewDidLayoutSubviews
{
    [super viewDidLayoutSubviews];
    CGRect f = self.view.bounds;

    self.titleLabel.frame = CGRectMake(0, 12, f.size.width, 28);
    self.statusLabel.frame = CGRectMake(16, 44, f.size.width - 32, 34);

    CGFloat circle = 160;
    CGFloat cy = 96 + 70;
    self.runButton.frame = CGRectMake((f.size.width - circle) / 2, cy, circle, circle);

    CGFloat logY = CGRectGetMaxY(self.runButton.frame) + 18;
    self.logLabel.frame = CGRectMake(16, logY, f.size.width - 32, 30);

    self.processTable.frame = CGRectMake(0, logY + 34, f.size.width, f.size.height - logY - 34 - 60);
}

- (void)startKernel
{
    Engine *engine = [Engine shared];
    NSString *err = [engine startKernel];
    if (err) {
        self.statusLabel.text = err;
        self.logLabel.text = err;
        self.runButton.enabled = NO;
        if ([err containsString:@"Reboot"] || [err containsString:@"already used"]) {
            [self.runButton setTitle:@"REBOOT" forState:UIControlStateNormal];
            [self.runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            self.runButton.backgroundColor = [UIColor colorWithRed:0.75 green:0.25 blue:0.20 alpha:1.0];
        } else {
            self.runButton.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
        }
    } else {
        [self updateStatus];
        [self refreshProcesses];
    }
}

- (void)updateStatus
{
    Engine *engine = [Engine shared];
    if (engine.attached) {
        self.statusLabel.text = [NSString stringWithFormat:@"attached: pid %d\nbackend: %@", engine.attachedPid, engine.backendName];
    } else {
        self.statusLabel.text = [NSString stringWithFormat:@"idle\nbackend: %@", engine.backendName];
    }
}

- (void)runTapped
{
    Engine *engine = [Engine shared];
    if (engine.attached) {
        [engine detach];
        self.logLabel.text = @"detached";
        [self updateStatus];
        [self updateRunButton];
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        @try {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logLabel.text = @"exploiting... (see log)";
            self.runButton.enabled = NO;
            self.runButton.alpha = 0.4;
        });
        pid_t pid = [self findPidOfProcess:kDefaultTargetProcess];
        NSString *err = nil;
        if (pid <= 0) {
            err = [NSString stringWithFormat:@"process '%@' not found — pick one from the list", kDefaultTargetProcess];
        } else {
            err = [engine attach:pid];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.runButton.enabled = YES;
            self.runButton.alpha = 1.0;
            self.logLabel.text = err ?: [NSString stringWithFormat:@"attached to %d\nKeep app open! Tap Stop before closing", pid];
            [self updateStatus];
            [self updateRunButton];
        });
        } @catch (NSException *e) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logLabel.text = [NSString stringWithFormat:@"error: %@", e.reason];
                self.runButton.enabled = YES;
                self.runButton.alpha = 1.0;
            });
        }
    });
}

- (void)updateRunButton
{
    BOOL attached = [Engine shared].attached;
    [self.runButton setTitle:attached ? @"Stop" : @"Run" forState:UIControlStateNormal];
    self.runButton.backgroundColor = attached
        ? [UIColor colorWithRed:0.75 green:0.22 blue:0.17 alpha:1.0]
        : [UIColor colorWithRed:0.10 green:0.55 blue:0.30 alpha:1.0];
}

- (pid_t)findPidOfProcess:(NSString *)name
{
    for (NSString *row in self.processes) {
        NSArray *parts = [row componentsSeparatedByString:@"\t"];
        if (parts.count == 2 && [parts[1] isEqualToString:name]) {
            return [(NSString *)parts[0] intValue];
        }
    }
    return -1;
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
            [self.processes removeAllObjects];
            [self.processes addObjectsFromArray:rows];
            [self.processTable reloadData];
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
    cell.backgroundColor = [UIColor clearColor];
    NSString *row = self.processes[indexPath.row];
    NSArray *parts = [row componentsSeparatedByString:@"\t"];
    cell.textLabel.text = parts.count == 2 ? parts[1] : row;
    cell.textLabel.textColor = [UIColor whiteColor];
    cell.detailTextLabel.text = parts.count == 2 ? parts[0] : @"";
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    cell.detailTextLabel.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
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
            self.runButton.enabled = YES;
            self.runButton.alpha = 1.0;
            self.logLabel.text = err ?: [NSString stringWithFormat:@"attached to %d\nKeep app open! Tap Stop before closing", pid];
            [self updateStatus];
            [self updateRunButton];
        });
    });
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    return self.processes.count ? @"processes (tap to attach)" : @"";
}

@end
