interface PageHeaderProps {
  title: string;
  description?: string;
}

export function PageHeader({ title, description }: PageHeaderProps) {
  return (
    <div className="mb-8">
      <h1 className="text-xl font-semibold text-text sm:text-2xl">{title}</h1>
      {description ? <p className="mt-1.5 max-w-2xl text-sm text-text-muted">{description}</p> : null}
    </div>
  );
}
