use concord_common::{FlowMeta, RouteState};
use smallvec::SmallVec;

use crate::eval::{Ev, Node, Yield};
use crate::observed::Observed;
use crate::prog::Op;
use crate::program::{MatchCtx, RouteProgram, RuleRef, Step};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Frame {
    prog: u32,
    op: u32,
    pos: u32,
}

#[derive(Clone, Copy, Debug)]
enum Advance {
    Leaf,
    Pos(u32),
}

enum Outcome {
    Next,
    Enter { sub: u32, from: u32 },
    Candidate { idx: u32, advance: Advance },
    Yield(Step<'static>),
}

/// The execution cursor over a program. It allocates only when `SUB-RULE`
/// nesting goes deeper than four lists.
pub struct Run<'p> {
    program: &'p RouteProgram,
    frames: SmallVec<[Frame; 4]>,
    root: u32,
    pending: Option<Advance>,
    replay: u32,
    observed: Observed,
}

impl<'p> Run<'p> {
    pub(crate) fn new(program: &'p RouteProgram, frames: SmallVec<[Frame; 4]>) -> Self {
        Run {
            program,
            frames,
            root: 0,
            pending: None,
            replay: 0,
            observed: Observed::default(),
        }
    }

    /// Restarts at a named list; unknown names use the main list, as `getRules` does.
    pub fn restart(&mut self, sub_rule: Option<&str>) {
        let prog = sub_rule
            .and_then(|name| {
                self.program
                    .sub_rule_names
                    .iter()
                    .position(|n| &**n == name)
            })
            .map_or(0, |index| index as u32 + 1);
        self.frames.clear();
        self.frames.push(Frame {
            prog,
            op: 0,
            pos: 0,
        });
        self.pending = None;
        self.replay = 0;
        self.root = 0;
    }

    /// Leaves an empty record behind.
    pub fn take_observed(&mut self) -> Observed {
        std::mem::take(&mut self.observed)
    }

    pub fn step(&mut self, flow: &FlowMeta, state: &RouteState, ctx: &MatchCtx<'_>) -> Step<'p> {
        let program = self.program;
        loop {
            let Some(&frame) = self.frames.last() else {
                return Step::Done;
            };
            let Some(prog) = program.progs.get(frame.prog as usize) else {
                self.frames.pop();
                continue;
            };
            let Some(op) = prog.ops.get(frame.op as usize) else {
                self.frames.pop();
                continue;
            };
            let mut ev = Ev::new(
                flow,
                state,
                ctx.geo,
                ctx.dscp,
                std::mem::take(&mut self.replay),
                std::mem::take(&mut self.observed),
            );
            let mut miss_end = None;
            let outcome = match *op {
                Op::Leaf { idx, node } => match prog.nodes.get(node as usize) {
                    None => Outcome::Next,
                    Some(node) => match ev.eval(node) {
                        Ok(false) => Outcome::Next,
                        Ok(true) => match node {
                            Node::SubRule { sub, .. } => Outcome::Enter {
                                sub: *sub,
                                from: idx,
                            },
                            _ => Outcome::Candidate {
                                idx,
                                advance: Advance::Leaf,
                            },
                        },
                        Err(why) => Outcome::Yield(self.yielded(why)),
                    },
                },
                Op::Host { idx, how } => {
                    if prog
                        .table
                        .payload(idx)
                        .is_some_and(|payload| how.matches(ev.host, payload))
                    {
                        Outcome::Candidate {
                            idx,
                            advance: Advance::Leaf,
                        }
                    } else {
                        Outcome::Next
                    }
                }
                Op::Domain(run) => match prog.domain_runs.get(run as usize) {
                    None => Outcome::Next,
                    Some(run) => {
                        miss_end = Some(run.end);
                        match run.next_from(ev.host, frame.pos, &prog.table) {
                            Some(idx) => Outcome::Candidate {
                                idx,
                                advance: Advance::Pos(idx + 1),
                            },
                            None => Outcome::Next,
                        }
                    }
                },
                Op::Ip(run) => match prog.ip_runs.get(run as usize) {
                    None => Outcome::Next,
                    Some(run) => {
                        miss_end = Some(run.end);
                        let ip = if run.src {
                            Ok(ev.src_ip())
                        } else {
                            ev.dst_ip(run.resolves)
                        };
                        match ip {
                            Err(why) => Outcome::Yield(self.yielded(why)),
                            Ok(ip) => match ip.and_then(|ip| run.next_from(ip, frame.pos)) {
                                Some(idx) => Outcome::Candidate {
                                    idx,
                                    advance: Advance::Pos(idx + 1),
                                },
                                None => Outcome::Next,
                            },
                        }
                    }
                },
            };
            self.observed = ev.observed;
            match outcome {
                Outcome::Yield(step) => return step,
                Outcome::Next => {
                    if let Some(top) = self.frames.last_mut() {
                        top.op += 1;
                        if let Some(end) = miss_end {
                            top.pos = end;
                        }
                    }
                }
                Outcome::Enter { sub, from } => {
                    if self.frames.len() == 1 {
                        self.root = from;
                    }
                    if let Some(top) = self.frames.last_mut() {
                        top.op += 1;
                    }
                    self.frames.push(Frame {
                        prog: sub + 1,
                        op: 0,
                        pos: 0,
                    });
                }
                Outcome::Candidate { idx, advance } => {
                    self.pending = Some(advance);
                    let target = prog
                        .table
                        .target(idx)
                        .map_or("", |id| program.target_name(id));
                    let rule = self.rule_ref(idx);
                    return Step::Candidate { target, rule };
                }
            }
        }
    }

    fn rule_ref(&self, index: u32) -> RuleRef {
        RuleRef(
            if self.frames.len() > 1 {
                self.root
            } else {
                index
            },
            self.frames.first().map_or(0, |frame| frame.prog),
        )
    }

    fn yielded(&mut self, why: Yield) -> Step<'static> {
        match why {
            Yield::Ip(counted) => {
                self.replay = counted;
                Step::NeedIp
            }
            Yield::Process => Step::NeedProcess,
        }
    }

    fn advance_top(&mut self) {
        let (Some(advance), Some(top)) = (self.pending.take(), self.frames.last_mut()) else {
            return;
        };
        match advance {
            Advance::Leaf => top.op += 1,
            Advance::Pos(pos) => top.pos = pos,
        }
    }

    /// The candidate cannot carry the flow (its target is `PASS`, or UDP is not
    /// supported): the main list goes on with its next rule.
    pub fn skip(&mut self) {
        if self.frames.len() > 1 {
            self.frames.truncate(1);
            self.pending = None;
        } else {
            self.advance_top();
        }
    }

    /// Whether the candidate just yielded came from a `SUB-RULE` list.
    pub fn in_sub_rule(&self) -> bool {
        self.frames.len() > 1
    }

    /// The candidate's target is `PASS-RULE`: a `SUB-RULE` list goes on with its
    /// own next rule.
    pub fn skip_pass_rule(&mut self) {
        self.advance_top();
    }
}
