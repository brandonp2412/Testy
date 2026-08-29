#!/usr/bin/env python3
"""Quality-gated Firefox unit-suite coverage vs CVE replication study."""
from __future__ import annotations
import argparse, json, math, re
from pathlib import Path
import numpy as np
import pandas as pd
import firefox_study as base

ROOT=Path(__file__).resolve().parent; BASE=ROOT/'data'/'firefox'; RAW=BASE/'raw'; PROCESSED=BASE/'processed'; CHARTS=ROOT/'charts'/'firefox'
PRIMARY_START=pd.Timestamp('2019-10-01'); PRIMARY_COVERAGE_END=pd.Timestamp('2025-09-30'); LAG_OUTCOME_END=pd.Timestamp('2025-12-31')
MAX_CANDIDATES_PER_MONTH=5; MIN_QUARTER_MONTHS=2; MIN_ANNUAL_MONTHS=10
MIN_ALL_LINES_TOTAL=1_000_000; MIN_ALL_COVERAGE_PCT=40.0; MAX_ALL_COVERAGE_PCT=85.0
PATTERN=re.compile(r'^mozilla-central/([^/]+)/([^/:]+):([^/]+)\.json\.zstd$')

def _candidate_frame(objects):
    by_revision={}
    for obj in objects:
        m=PATTERN.match(obj.get('name',''))
        if not m: continue
        revision,platform,suite=m.groups(); stream=f'{platform}:{suite}'
        if stream not in base.REQUIRED_STREAMS: continue
        by_revision.setdefault(revision,{})[stream]=obj
    rows=[]
    for revision,streams in by_revision.items():
        if not all(s in streams for s in base.REQUIRED_STREAMS): continue
        times=[pd.to_datetime(streams[s]['updated'],utc=True) for s in base.REQUIRED_STREAMS]; report_time=max(times)
        row={'revision':revision,'report_time':report_time,'month':report_time.to_period('M').strftime('%Y-%m')}
        for stream in base.REQUIRED_STREAMS:
            row[stream]=streams[stream]['name']; row[f'{stream}_bytes']=int(streams[stream].get('size',0) or 0)
        rows.append(row)
    frame=pd.DataFrame(rows).sort_values('report_time').reset_index(drop=True)
    if frame.empty: raise RuntimeError('No Firefox revisions contain all required coverage streams')
    return frame

def rank_monthly_candidates(objects):
    frame=_candidate_frame(objects); ranked=[]; size_cols=[f'{s}_bytes' for s in base.REQUIRED_STREAMS]
    for month,group in frame.groupby('month',sort=True):
        group=group.copy(); target=pd.Timestamp(pd.Period(month,'M').start_time,tz='UTC')+pd.Timedelta(days=14,hours=12); score=np.zeros(len(group))
        for col in size_cols:
            logs=np.log(np.maximum(group[col].astype(float).to_numpy(),1.0)); med=float(np.median(logs)); mad=float(np.median(np.abs(logs-med))); scale=max(mad*1.4826,0.05); score+=np.abs(logs-med)/scale
        days=(group['report_time']-target).abs().dt.total_seconds()/86400.0; group['candidate_score']=score+days.to_numpy()*0.02
        group=group.sort_values(['candidate_score','report_time']).head(MAX_CANDIDATES_PER_MONTH); group['candidate_rank']=np.arange(1,len(group)+1); ranked.append(group)
    return pd.concat(ranked,ignore_index=True).sort_values(['month','candidate_rank'])

def quality_reasons(obs):
    reasons=[]; total=int(obs.get('all_tests_lines_total',0)); covered=int(obs.get('all_tests_root_lines_covered',0)); all_pct=float(obs.get('all_tests_root_coverage_pct',0)); unit=int(obs.get('unit_union_lines_covered',0)); unit_pct=float(obs.get('unit_union_coverage_pct',0))
    if total<MIN_ALL_LINES_TOTAL: reasons.append('all_tests_denominator_too_small')
    if not MIN_ALL_COVERAGE_PCT<=all_pct<=MAX_ALL_COVERAGE_PCT: reasons.append('all_tests_coverage_out_of_range')
    if covered<=0 or covered>total: reasons.append('invalid_all_tests_covered_count')
    if unit<=0: reasons.append('no_unit_lines_covered')
    if covered>0 and unit>covered: reasons.append('unit_union_exceeds_all_tests_covered')
    if unit_pct>all_pct+0.25: reasons.append('unit_union_pct_exceeds_all_tests_pct')
    recomputed=100.0*covered/total if total else float('nan')
    if math.isfinite(recomputed) and abs(recomputed-all_pct)>0.75: reasons.append('all_tests_root_metadata_inconsistent')
    for suite in ('gtest','cppunittest','xpcshell'):
        if int(obs.get(f'{suite}_root_lines_total',0))<=0: reasons.append(f'{suite}_empty')
    return reasons

def _mark_isolated_denominator_outliers(frame):
    out=frame.sort_values('month').reset_index(drop=True).copy(); out['analysis_quality_ok']=True; out['quality_note']=''; by_month={pd.Period(m,'M'):i for i,m in enumerate(out['month'])}
    for period,i in list(by_month.items()):
        pi=by_month.get(period-1); ni=by_month.get(period+1)
        if pi is None or ni is None: continue
        pv=float(out.loc[pi,'all_tests_lines_total']); cv=float(out.loc[i,'all_tests_lines_total']); nv=float(out.loc[ni,'all_tests_lines_total'])
        if min(pv,nv)<=0: continue
        neighbor_ratio=max(pv,nv)/min(pv,nv); median=(pv+nv)/2; ratio=cv/median
        if neighbor_ratio<=1.20 and not 0.65<=ratio<=1.55:
            out.loc[i,'analysis_quality_ok']=False; out.loc[i,'quality_note']='isolated_denominator_outlier'
    return out

def collect_coverage():
    RAW.mkdir(parents=True,exist_ok=True); candidates=rank_monthly_candidates(base.list_coverage_objects()); candidates.to_csv(RAW/'coverage_candidate_manifest.csv',index=False); selected=[]; audit=[]
    for month,group in candidates.groupby('month',sort=True):
        accepted=None
        for _,row in group.sort_values('candidate_rank').iterrows():
            try: obs=base.coverage_observation(row); reasons=quality_reasons(obs)
            except Exception as exc: obs=None; reasons=[f'exception:{type(exc).__name__}:{exc}']
            audit.append({'month':month,'candidate_rank':int(row['candidate_rank']),'candidate_score':float(row['candidate_score']),'revision':row['revision'],'accepted':not reasons,'reasons':';'.join(reasons),'all_tests_lines_total':obs.get('all_tests_lines_total') if obs else None,'all_tests_root_coverage_pct':obs.get('all_tests_root_coverage_pct') if obs else None,'unit_union_coverage_pct':obs.get('unit_union_coverage_pct') if obs else None})
            if not reasons:
                obs['candidate_rank']=int(row['candidate_rank']); obs['candidate_score']=float(row['candidate_score']); accepted=obs; break
        if accepted is None: print(f'coverage month {month}: no quality-passing report',flush=True); continue
        selected.append(accepted); print(f"coverage month {month}: selected rank {accepted['candidate_rank']} all={accepted['all_tests_root_coverage_pct']:.2f}% unit={accepted['unit_union_coverage_pct']:.2f}%",flush=True)
        pd.DataFrame(selected).to_csv(RAW/'unit_coverage_monthly.csv',index=False); pd.DataFrame(audit).to_csv(RAW/'coverage_quality_audit.csv',index=False)
    frame=pd.DataFrame(selected)
    if frame.empty: raise RuntimeError('No Firefox monthly coverage observations passed quality gates')
    frame=_mark_isolated_denominator_outliers(frame); frame.to_csv(RAW/'unit_coverage_monthly.csv',index=False); pd.DataFrame(audit).to_csv(RAW/'coverage_quality_audit.csv',index=False); return frame

def _quality_mask(frame):
    if 'analysis_quality_ok' not in frame.columns: return pd.Series(True,index=frame.index)
    return frame['analysis_quality_ok'].astype(str).str.lower().eq('true')

def lag_quarters(quarterly,cves):
    cv=cves.copy(); cv['date']=pd.to_datetime(cv['announced_date']); cv['period_obj']=cv['date'].dt.to_period('Q'); counts=cv.groupby('period_obj')['cve'].nunique().to_dict(); rows=[]
    for _,row in quarterly.iterrows():
        period=pd.Period(str(row['period']),freq='Q'); nxt=period+1
        if nxt.end_time.normalize()>LAG_OUTCOME_END: continue
        rec=row.to_dict(); rec['next_quarter']=str(nxt); rec['next_quarter_cves']=int(counts.get(nxt,0)); rows.append(rec)
    return pd.DataFrame(rows)

def analyze():
    PROCESSED.mkdir(parents=True,exist_ok=True); coverage_all=pd.read_csv(RAW/'unit_coverage_monthly.csv'); cves_all=pd.read_csv(RAW/'firefox_cves.csv'); coverage_all['date']=pd.to_datetime(coverage_all['report_time_utc'],utc=True).dt.tz_convert(None); quality=_quality_mask(coverage_all); coverage_good=coverage_all[quality].copy()
    primary_cov=coverage_good[(coverage_good['date']>=PRIMARY_START)&(coverage_good['date']<=PRIMARY_COVERAGE_END)].copy(); cve_dates=pd.to_datetime(cves_all['announced_date']); same_cves=cves_all[(cve_dates>=PRIMARY_START)&(cve_dates<=PRIMARY_COVERAGE_END)].copy(); lag_cves=cves_all[(cve_dates>=PRIMARY_START)&(cve_dates<=LAG_OUTCOME_END)].copy()
    monthly=base.aggregate(primary_cov,same_cves,'M'); quarterly=base.aggregate(primary_cov,same_cves,'Q'); quarterly=quarterly[quarterly['coverage_observations']>=MIN_QUARTER_MONTHS].copy(); lagged=lag_quarters(quarterly,lag_cves); annual=base.aggregate(primary_cov,lag_cves,'Y'); annual=annual[annual['coverage_observations']>=MIN_ANNUAL_MONTHS].copy()
    monthly.to_csv(PROCESSED/'monthly.csv',index=False); quarterly.to_csv(PROCESSED/'quarterly.csv',index=False); lagged.to_csv(PROCESSED/'quarterly_lag1.csv',index=False); annual.to_csv(PROCESSED/'annual.csv',index=False)
    base.aggregate(coverage_good,cves_all,'M').to_csv(PROCESSED/'monthly_all.csv',index=False); base.aggregate(coverage_good,cves_all,'Q').to_csv(PROCESSED/'quarterly_all.csv',index=False); base.aggregate(coverage_good,cves_all,'Y').to_csv(PROCESSED/'annual_all.csv',index=False)
    expected_months=pd.period_range(PRIMARY_START,PRIMARY_COVERAGE_END,freq='M'); observed_months=set(pd.Period(m,'M') for m in primary_cov['month'].astype(str)); missing_months=[str(m) for m in expected_months if m not in observed_months]; expected_quarters=pd.period_range('2019Q4','2025Q3',freq='Q'); observed_quarters=set(pd.Period(p,'Q') for p in quarterly['period'].astype(str)); missing_quarters=[str(q) for q in expected_quarters if q not in observed_quarters]
    audit=pd.read_csv(RAW/'coverage_quality_audit.csv') if (RAW/'coverage_quality_audit.csv').exists() else pd.DataFrame(); rejected=int((~audit['accepted'].astype(str).str.lower().eq('true')).sum()) if not audit.empty else 0; quality_excluded=coverage_all.loc[~quality,'month'].astype(str).tolist(); late=coverage_all[coverage_all['month'].astype(str).str.match(r'2025-(07|08|09|10|11|12)')]; late_denoms={str(r.month):int(r.all_tests_lines_total) for r in late.itertuples()}
    stats={'metric':'union of lines covered by all:gtest, all:cppunittest and all:xpcshell divided by same-revision all:all linesTotal','primary_coverage_window':{'start':'2019-10-01','end':'2025-09-30'},'lag_outcome_end':'2025-12-31','coverage_archive_first_sample':str(coverage_all['month'].min()),'coverage_archive_last_sample':str(coverage_all['month'].max()),'selected_monthly_samples':int(len(coverage_all)),'quality_eligible_monthly_samples':int(len(coverage_good)),'primary_quality_eligible_monthly_samples':int(len(primary_cov)),'quality_excluded_months':quality_excluded,'candidate_attempts_rejected':rejected,'missing_primary_months':missing_months,'missing_primary_quarters':missing_quarters,'known_archive_gap':{'start':'2024-10','end':'2025-06'},'late_2025_denominators':late_denoms,'same_period_unique_cves':int(same_cves['cve'].nunique()),'lag_window_unique_cves':int(lag_cves['cve'].nunique()),'quarterly_same_period':base.association(quarterly,'unit_coverage_pct','cves_reported'),'quarterly_next_period':base.association(lagged,'unit_coverage_pct','next_quarter_cves'),'annual_same_period':base.association(annual,'unit_coverage_pct','cves_reported')}
    (PROCESSED/'stats.json').write_text(json.dumps(stats,indent=2)+'\n',encoding='utf-8'); return stats

def history_svg(coverage,out):
    df=coverage[_quality_mask(coverage)].copy(); df['date']=pd.to_datetime(df['report_time_utc'],utc=True).dt.tz_convert(None); df=df[(df['date']>=PRIMARY_START)&(df['date']<=PRIMARY_COVERAGE_END)].sort_values('date')
    if df.empty: return
    width,height=1400,720; left,right,top,bottom=110,70,155,95; pw,ph=width-left-right,height-top-bottom; y=df['unit_union_coverage_pct'].astype(float).to_numpy(); pad=max((y.max()-y.min())*.12,1.0); y0,y1=max(0.0,y.min()-pad),min(100.0,y.max()+pad); d0,d1=PRIMARY_START,PRIMARY_COVERAGE_END
    sx=lambda d:left+(pd.Timestamp(d)-d0).total_seconds()/(d1-d0).total_seconds()*pw; sy=lambda v:top+ph-(float(v)-y0)/(y1-y0)*ph; parts=base.svg_start('Firefox unit-suite coverage history','Quality-gated monthly original CI reports · archive gap is left unconnected',width,height); parts.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" rx="18" fill="{base.PANEL}"/>')
    gx0,gx1=sx(pd.Timestamp('2024-10-01')),sx(pd.Timestamp('2025-07-01')); parts.append(f'<rect x="{gx0:.1f}" y="{top}" width="{gx1-gx0:.1f}" height="{ph}" fill="{base.CORAL}" opacity="0.07"/>'); parts.append(f'<text x="{(gx0+gx1)/2:.1f}" y="{top+30}" text-anchor="middle" fill="{base.CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="14">Mozilla coverage archive gap</text>')
    for tick in base.axis_ticks(y0,y1): yy=sy(tick); parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+pw}" y2="{yy:.1f}" stroke="{base.GRID}"/>'); parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{base.MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')
    for year in range(2020,2026): dt=pd.Timestamp(year=year,month=1,day=1); xx=sx(dt); parts.append(f'<line x1="{xx:.1f}" y1="{top}" x2="{xx:.1f}" y2="{top+ph}" stroke="{base.GRID}" stroke-dasharray="4 8"/>'); parts.append(f'<text x="{xx:.1f}" y="{top+ph+34}" text-anchor="middle" fill="{base.MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{year}</text>')
    segment=[]; prev=None
    for r in df.itertuples():
        period=pd.Period(str(r.month),'M')
        if prev is not None and period!=prev+1:
            if len(segment)>=2: pts=' '.join(f'{sx(d):.1f},{sy(v):.1f}' for d,v in segment); parts.append(f'<polyline points="{pts}" fill="none" stroke="{base.BLUE}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
            segment=[]
        segment.append((pd.Timestamp(r.date),float(r.unit_union_coverage_pct))); prev=period
    if len(segment)>=2: pts=' '.join(f'{sx(d):.1f},{sy(v):.1f}' for d,v in segment); parts.append(f'<polyline points="{pts}" fill="none" stroke="{base.BLUE}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
    for r in df.itertuples(): parts.append(f'<circle cx="{sx(r.date):.1f}" cy="{sy(r.unit_union_coverage_pct):.1f}" r="3.5" fill="{base.BLUE}"/>')
    parts.append('</svg>'); out.write_text('\n'.join(parts),encoding='utf-8')

def render_charts():
    CHARTS.mkdir(parents=True,exist_ok=True); annual=pd.read_csv(PROCESSED/'annual.csv'); quarterly=pd.read_csv(PROCESSED/'quarterly.csv'); lagged=pd.read_csv(PROCESSED/'quarterly_lag1.csv'); coverage=pd.read_csv(RAW/'unit_coverage_monthly.csv')
    base.annual_svg(annual,CHARTS/'annual_coverage_vs_cves.svg'); p=CHARTS/'annual_coverage_vs_cves.svg'; p.write_text(p.read_text().replace('Annual primary view: complete years 2020–2025','Annual view: years with ≥10 quality-gated monthly coverage samples'))
    base.scatter_svg(quarterly,'cves_reported','Firefox quarterly unit coverage vs CVEs','Quality-gated available quarters, 2019 Q4–2025 Q3 · archive gap shown separately',CHARTS/'quarterly_same_period_scatter.svg'); base.scatter_svg(lagged,'next_quarter_cves','Does Firefox unit coverage predict next-quarter CVEs?','Strict calendar Q→Q+1 outcomes · coverage gaps never skip forward',CHARTS/'quarterly_lag1_scatter.svg'); history_svg(coverage,CHARTS/'unit_coverage_history.svg')

def fmt(v): return f'{float(v):+.3f}' if v is not None and math.isfinite(float(v)) else 'n/a'
def write_results(stats):
    annual=pd.read_csv(PROCESSED/'annual.csv'); same=stats['quarterly_same_period']; lag=stats['quarterly_next_period']; rows='\n'.join(f'| {r.period} | {r.unit_coverage_pct:.2f}% | {int(r.cves_reported)} | {int(r.coverage_observations)} |' for r in annual.itertuples()); missing=', '.join(stats['missing_primary_quarters']) or 'none'; excluded=', '.join(stats['quality_excluded_months']) or 'none'
    text=f'''# Firefox results

This is the quality-gated Firefox replication of the Chromium study. It uses Mozilla's original public `mozilla-central` coverage archive and Mozilla's Firefox security advisories.

## Coverage metric

For each month, Testy considers up to five original revisions containing `all:gtest`, `all:cppunittest`, `all:xpcshell`, and `all:all`. Candidates are ranked by robust within-month compressed-report size and checked for plausible full-report metadata. The metric is the **union of exact source lines covered by GTest + CppUnitTest + XPCShell**, divided by the same-revision `all:all` executable-line denominator. Candidate attempts and rejection reasons are retained in `data/firefox/raw/coverage_quality_audit.csv`.

## Primary result

The exposure window is **2019 Q4 through 2025 Q3**, but Mozilla's archive has no usable coverage from **2024 Q4 through 2025 Q2**. Those quarters are missing rather than interpolated.

Across **{same['n']} available quality-gated quarters**, same-quarter Firefox unit-suite coverage vs CVEs has Pearson **r = {fmt(same['pearson_r'])}** (naive IID bootstrap 95% CI {fmt(same['pearson_bootstrap_95pct_ci'][0])} to {fmt(same['pearson_bootstrap_95pct_ci'][1])}) and Spearman **rho = {fmt(same['spearman_rho'])}**.

For the lagged analysis, each coverage quarter Q is matched to the **actual calendar Q+1**, even when Q+1 has no coverage measurement. Coverage in Q versus CVEs first disclosed in Q+1 has Pearson **r = {fmt(lag['pearson_r'])}** across **{lag['n']} quarter pairs** (naive IID bootstrap 95% CI {fmt(lag['pearson_bootstrap_95pct_ci'][0])} to {fmt(lag['pearson_bootstrap_95pct_ci'][1])}); Spearman **rho = {fmt(lag['spearman_rho'])}**.

These are observational associations, not causal estimates.

![Firefox quarterly scatter](charts/firefox/quarterly_same_period_scatter.svg)

![Firefox lagged scatter](charts/firefox/quarterly_lag1_scatter.svg)

![Firefox unit coverage history](charts/firefox/unit_coverage_history.svg)

![Firefox annual coverage and CVEs](charts/firefox/annual_coverage_vs_cves.svg)

## Data-quality boundaries

- Original coverage archive begins in September 2019.
- **2024-10 through 2025-06:** no usable complete unit-suite coverage revisions exist. Linux-specific streams have the same gap.
- Predictor coverage stops at **2025-09-30**. Q4 2025 CVEs remain usable as the outcome for Q3 coverage without treating late-2025 coverage as comparable.
- Missing primary quarters: **{missing}**.
- Isolated selected months rejected by longitudinal denominator checking: **{excluded}**.
- Candidate report attempts rejected by static quality gates: **{stats['candidate_attempts_rejected']}**.

No missing coverage is interpolated, and lagging never jumps across a coverage gap.

## Annual descriptive data

Only years with at least {MIN_ANNUAL_MONTHS} quality-gated monthly coverage samples are shown.

| Year | Mean unit-suite coverage | Unique Firefox CVEs | Coverage months |
| --- | ---: | ---: | ---: |
{rows}

## Dataset

- Selected monthly original-CI samples: **{stats['selected_monthly_samples']}**, from **{stats['coverage_archive_first_sample']}** through **{stats['coverage_archive_last_sample']}**.
- Quality-eligible selected samples: **{stats['quality_eligible_monthly_samples']}**.
- Primary quality-eligible exposure samples through 2025 Q3: **{stats['primary_quality_eligible_monthly_samples']}**.
- Same-period Firefox CVEs through 2025 Q3: **{stats['same_period_unique_cves']}**.
- Lag outcomes are allowed through 2025 Q4.

## Sources

- Historical raw coverage: `gs://relman-code-coverage-prod/mozilla-central`
- Mozilla coverage documentation: {base.COVERAGE_DOC}
- Firefox advisories: {base.ADVISORY_INDEX}
- GTest documentation: {base.GTEST_DOC}
- XPCShell documentation: {base.XPCSHELL_DOC}
- Taskcluster unit-test metadata: {base.TASK_ATTR_DOC}

## Interpretation limits

1. CVEs measure discovered/disclosed vulnerabilities, not latent vulnerabilities.
2. The metric covers three long-running unit-oriented suites, not every Mozilla test that could be called a unit test.
3. The same-revision `all:all` denominator can change when instrumentation/build scope changes; late-2025 predictor data is therefore not mixed into the primary exposure series.
4. Coverage-report upload time is the sample timestamp rather than Mercurial commit time.
5. The IID bootstrap does not account for time-series autocorrelation.
6. Coverage can co-move with code churn, fuzzing, sanitizers, architecture changes, researcher attention, and other security work.
'''; (ROOT/'FIREFOX_RESULTS.md').write_text(text,encoding='utf-8')

def run_all(): collect_coverage(); base.collect_cves(); stats=analyze(); render_charts(); write_results(stats); return stats
def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('command',nargs='?',choices=['collect','analyze','charts','all'],default='all'); args=parser.parse_args()
    if args.command in {'collect','all'}: collect_coverage(); base.collect_cves()
    if args.command in {'analyze','all'}: stats=analyze(); write_results(stats)
    if args.command in {'charts','all'}: render_charts()
if __name__=='__main__': main()
